// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/plugin_service_impl.h"

#include <stddef.h>

#include <string>
#include <utility>
#include <iostream>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/post_task.h"
#include "base/task/thread_pool.h"
#include "base/task_runner_util.h"
#include "base/threading/thread.h"
#include "build/build_config.h"
#include "content/browser/child_process_security_policy_impl.h"
#include "content/browser/plugin_list.h"
#include "content/browser/ppapi_plugin_process_host.h"
#include "content/browser/renderer_host/render_process_host_impl.h"
#include "content/browser/renderer_host/render_view_host_impl.h"
#include "content/browser/web_contents/web_contents_impl.h"
#include "content/common/content_switches_internal.h"
#include "content/common/pepper_plugin_list.h"
#include "content/common/view_messages.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/content_browser_client.h"
#include "content/public/browser/plugin_service_filter.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/resource_context.h"
#include "content/public/browser/web_contents.h"
#include "content/public/common/content_client.h"
#include "content/public/common/content_constants.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/process_type.h"
#include "content/public/common/webplugininfo.h"
#include "ppapi/shared_impl/ppapi_permissions.h"
#include "services/metrics/public/cpp/ukm_builders.h"

#if defined(OS_WIN)
#include "content/common/plugin_constants_win.h"
#include "ui/gfx/win/hwnd_util.h"
#endif

#if defined(OS_POSIX) && !defined(OS_OPENBSD) && !defined(OS_ANDROID)
using ::base::FilePathWatcher;
#endif

namespace content {
namespace {

// This enum is used to collect Flash usage data.
enum FlashUsage {
#if defined(USE_UNIONTECH_NPAPI)
  // Number of browser processes that have started at least one NPAPI Flash
  // process during their lifetime.
  START_NPAPI_FLASH_AT_LEAST_ONCE,
#endif
  // Number of browser processes that have started at least one PPAPI Flash
  // process during their lifetime.
  START_PPAPI_FLASH_AT_LEAST_ONCE = 1,
  // Total number of browser processes.
  TOTAL_BROWSER_PROCESSES,
  FLASH_USAGE_ENUM_COUNT
};

#if defined(USE_UNIONTECH_NPAPI)
enum NPAPIPluginStatus {
  // Platform does not support NPAPI.
  NPAPI_STATUS_UNSUPPORTED,
  // Platform supports NPAPI and NPAPI is disabled.
  NPAPI_STATUS_DISABLED,
  // Platform supports NPAPI and NPAPI is enabled.
  NPAPI_STATUS_ENABLED,
  NPAPI_STATUS_ENUM_COUNT
};
#endif

// Callback set on the PluginList to assert that plugin loading happens on the
// correct thread.
void WillLoadPluginsCallback(base::SequenceChecker* sequence_checker) {
  DCHECK(sequence_checker->CalledOnValidSequence());
}

#if defined(USE_UNIONTECH_NPAPI)
#if defined(OS_MACOSX)
void NotifyPluginsOfActivation() {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);
  for (PluginProcessHostIterator iter; !iter.Done(); ++iter)
    iter->OnAppActivation();
}
#endif

#if defined(OS_POSIX)
#if !defined(OS_OPENBSD) && !defined(OS_ANDROID)
void NotifyPluginDirChanged(const base::FilePath& path, bool error) {
  if (error) {
    // TODO(pastarmovj): Add some sensible error handling. Maybe silently
    // stopping the watcher would be enough. Or possibly restart it.
    NOTREACHED();
    return;
  }
  VLOG(1) << "Watched path changed: " << path.value();
  // Make the plugin list update itself
  PluginList::Singleton()->RefreshPlugins();

  base::PostTask(
      FROM_HERE, BrowserThread::UI,
      base::Bind(&PluginService::PurgePluginListCache,
                  static_cast<BrowserContext*>(NULL), false));
}
#endif  // !defined(OS_OPENBSD) && !defined(OS_ANDROID)

#if defined(USE_UNIONTECH_NPAPI_NOUSE)
void ForwardCallback(base::SingleThreadTaskRunner* target_task_runner,
                     const PluginService::GetPluginsCallback& callback,   
                     const std::vector<WebPluginInfo>& plugins) {
  target_task_runner->PostTask(FROM_HERE, base::BindOnce([&callback, &plugins](){
    callback.Run( plugins);
  }));
}
#endif
#endif  // defined(OS_POSIX)
#endif

}  // namespace

// static
void PluginServiceImpl::RecordBrokerUsage(int render_process_id,
                                          int render_frame_id) {
  WebContents* web_contents = WebContents::FromRenderFrameHost(
      RenderFrameHost::FromID(render_process_id, render_frame_id));
  if (web_contents) {
    ukm::SourceId source_id = static_cast<WebContentsImpl*>(web_contents)
                                  ->GetUkmSourceIdForLastCommittedSource();
    ukm::builders::Pepper_Broker(source_id).Record(ukm::UkmRecorder::Get());
  }
}

// static
PluginService* PluginService::GetInstance() {
  return PluginServiceImpl::GetInstance();
}

void PluginService::PurgePluginListCache(BrowserContext* browser_context,
                                         bool reload_pages) {
  for (RenderProcessHost::iterator it = RenderProcessHost::AllHostsIterator();
       !it.IsAtEnd(); it.Advance()) {
    RenderProcessHost* host = it.GetCurrentValue();
    if (!browser_context || host->GetBrowserContext() == browser_context)
      host->GetRendererInterface()->PurgePluginListCache(reload_pages);
  }
}

// static
PluginServiceImpl* PluginServiceImpl::GetInstance() {
  return base::Singleton<PluginServiceImpl>::get();
}

PluginServiceImpl::PluginServiceImpl()
    : npapi_plugins_enabled_(false), filter_(NULL) {
  plugin_list_sequence_checker_.DetachFromSequence();

  // Collect the total number of browser processes (which create
  // PluginServiceImpl objects, to be precise). The number is used to normalize
  // the number of processes which start at least one NPAPI/PPAPI Flash process.
  static bool counted = false;
  if (!counted) {
    counted = true;
    UMA_HISTOGRAM_ENUMERATION("Plugin.FlashUsage", TOTAL_BROWSER_PROCESSES,
                              FLASH_USAGE_ENUM_COUNT);
  }
}

PluginServiceImpl::~PluginServiceImpl() {
#if defined(USE_UNIONTECH_NPAPI)
  // Make sure no plugin channel requests have been leaked.
  DCHECK(pending_plugin_clients_.empty());
#endif
}

void PluginServiceImpl::Init() {
  plugin_list_task_runner_ = base::ThreadPool::CreateSequencedTaskRunner(
      {base::MayBlock(), base::TaskPriority::USER_VISIBLE,
       base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN});

  // Setup the sequence checker right after setting up the task runner.
  //plugin_list_sequence_checker_.DetachFromSequence();
  PluginList::Singleton()->set_will_load_plugins_callback(base::BindRepeating(
      &WillLoadPluginsCallback, &plugin_list_sequence_checker_));

  RegisterPepperPlugins();
#if defined(USE_UNIONTECH_NPAPI)
  // Load any specified on the command line as well.
  const base::CommandLine* command_line =
      base::CommandLine::ForCurrentProcess();
  base::FilePath path =
      command_line->GetSwitchValuePath(switches::kLoadPlugin);
  if (!path.empty())    
    PluginList::Singleton()->AddExtraPluginPath(path);
  path = command_line->GetSwitchValuePath(switches::kExtraPluginDir);
  if (!path.empty())
    PluginList::Singleton()->AddExtraPluginDir(path);

  if (command_line->HasSwitch(switches::kDisablePluginsDiscovery))
    PluginList::Singleton()->DisablePluginsDiscovery();
#endif
}
#if defined(USE_UNIONTECH_NPAPI)
void PluginServiceImpl::StartWatchingPlugins() {
  // Start watching for changes in the plugin list. This means watching
  // for changes in the Windows registry keys and on both Windows and POSIX
  // watch for changes in the paths that are expected to contain plugins.
#if defined(OS_WIN)
  if (hkcu_key_.Create(HKEY_CURRENT_USER,
                       kRegistryMozillaPlugins,
                       KEY_NOTIFY) == ERROR_SUCCESS) {
    base::win::RegKey::ChangeCallback callback =
        base::Bind(&PluginServiceImpl::OnKeyChanged, base::Unretained(this),
                   base::Unretained(&hkcu_key_));
    hkcu_key_.StartWatching(callback);
  }
  if (hklm_key_.Create(HKEY_LOCAL_MACHINE,
                       kRegistryMozillaPlugins,
                       KEY_NOTIFY) == ERROR_SUCCESS) {
    base::win::RegKey::ChangeCallback callback =
        base::Bind(&PluginServiceImpl::OnKeyChanged, base::Unretained(this),
                   base::Unretained(&hklm_key_));
    hklm_key_.StartWatching(callback);
  }
#endif
#if defined(OS_POSIX) && !defined(OS_OPENBSD) && !defined(OS_ANDROID)
// On ChromeOS the user can't install plugins anyway and on Windows all
// important plugins register themselves in the registry so no need to do that.

  // Get the list of all paths for registering the FilePathWatchers
  // that will track and if needed reload the list of plugins on runtime.
  std::vector<base::FilePath> plugin_dirs;
  PluginList::Singleton()->GetPluginDirectories(&plugin_dirs);

  for (size_t i = 0; i < plugin_dirs.size(); ++i) {
    // FilePathWatcher can not handle non-absolute paths under windows.
    // We don't watch for file changes in windows now but if this should ever
    // be extended to Windows these lines might save some time of debugging.
#if defined(OS_WIN)
    if (!plugin_dirs[i].IsAbsolute())
      continue;
#endif

    FilePathWatcher* watcher = new FilePathWatcher();
    VLOG(1) << "Watching for changes in: " << plugin_dirs[i].value();
    base::PostTask(
        FROM_HERE, BrowserThread::IO,
        base::Bind(&PluginServiceImpl::RegisterFilePathWatcher, watcher, plugin_dirs[i]));
    file_watchers_.push_back(watcher);

  }
#endif
}

PluginProcessHost* PluginServiceImpl::FindNpapiPluginProcess(
    const base::FilePath& plugin_path) {
  for (PluginProcessHostIterator iter; !iter.Done(); ++iter) {
    if (iter->info().path == plugin_path)
      return *iter;
  }

  return NULL;
  }
#endif

PpapiPluginProcessHost* PluginServiceImpl::FindPpapiPluginProcess(
    const base::FilePath& plugin_path,
    const base::FilePath& profile_data_directory,
    const base::Optional<url::Origin>& origin_lock) {
  for (PpapiPluginProcessHostIterator iter; !iter.Done(); ++iter) {
    if (iter->plugin_path() == plugin_path &&
        iter->profile_data_directory() == profile_data_directory &&
        (!iter->origin_lock() || iter->origin_lock() == origin_lock)) {
      return *iter;
    }
  }
  return nullptr;
}

int PluginServiceImpl::CountPpapiPluginProcessesForProfile(
    const base::FilePath& plugin_path,
    const base::FilePath& profile_data_directory) {
  int count = 0;
  for (PpapiPluginProcessHostIterator iter; !iter.Done(); ++iter) {
    if (iter->plugin_path() == plugin_path &&
        iter->profile_data_directory() == profile_data_directory) {
      ++count;
    }
  }
  return count;
}

PpapiPluginProcessHost* PluginServiceImpl::FindPpapiBrokerProcess(
    const base::FilePath& broker_path) {
  for (PpapiBrokerProcessHostIterator iter; !iter.Done(); ++iter) {
    if (iter->plugin_path() == broker_path)
      return *iter;
  }

  return nullptr;
}
#if defined(USE_UNIONTECH_NPAPI)
PluginProcessHost* PluginServiceImpl::FindOrStartNpapiPluginProcess(
    int render_process_id,
    const base::FilePath& plugin_path) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);

  if (filter_ && !filter_->CanLoadPlugin(render_process_id, plugin_path))
    return NULL;

  PluginProcessHost* plugin_host = FindNpapiPluginProcess(plugin_path);
  if (plugin_host)
    return plugin_host;

  WebPluginInfo info;
  if (!GetPluginInfoByPath(plugin_path, &info)) {
    return NULL;
  }

  // Record when NPAPI Flash process is started for the first time.
  static bool counted = false;
  if (!counted && base::UTF16ToUTF8(info.name) == kFlashPluginName) {
    counted = true;
    UMA_HISTOGRAM_ENUMERATION("Plugin.FlashUsage",
                              START_NPAPI_FLASH_AT_LEAST_ONCE,
                              FLASH_USAGE_ENUM_COUNT);
  }
#if defined(OS_CHROMEOS)
  // TODO(ihf): Move to an earlier place once crbug.com/314301 is fixed. For now
  // we still want Plugin.FlashUsage recorded if we end up here.
  LOG(WARNING) << "Refusing to start npapi plugin on ChromeOS.";
  return NULL;
#endif
  // This plugin isn't loaded by any plugin process, so create a new process.
  LOG(INFO) << "----[NPAPI] Create PluginProcessHost ----";
  std::unique_ptr<PluginProcessHost> new_host(new PluginProcessHost());
  if (!new_host->Init(info)) {
    NOTREACHED();  // Init is not expected to fail.
    return NULL;
  }
  return new_host.release();
}
#endif

PpapiPluginProcessHost* PluginServiceImpl::FindOrStartPpapiPluginProcess(
    int render_process_id,
    const url::Origin& embedder_origin,
    const base::FilePath& plugin_path,
    const base::FilePath& profile_data_directory,
    const base::Optional<url::Origin>& origin_lock) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);

  if (filter_ && !filter_->CanLoadPlugin(render_process_id, plugin_path)) {
    VLOG(1) << "Unable to load ppapi plugin: " << plugin_path.MaybeAsASCII();
    return nullptr;
  }

  // Validate that the plugin is actually registered.
  const PepperPluginInfo* info = GetRegisteredPpapiPluginInfo(plugin_path);
  if (!info) {
    VLOG(1) << "Unable to find ppapi plugin registration for: "
            << plugin_path.MaybeAsASCII();
    return nullptr;
  }

  // Validate that |embedder_origin| is allowed to embed the plugin.
  if (!GetContentClient()->browser()->ShouldAllowPluginCreation(embedder_origin,
                                                                *info)) {
    return nullptr;
  }

  if (info->permissions & ppapi::PERMISSION_FLASH) {
    // Flash has its own flavour of CORS, so CORB needs to allow all responses
    // and rely on Flash to enforce same-origin policy.  See also
    // https://crbug.com/874515 and https://crbug.com/816318#c5.
    //
    // Note that ppapi::PERMISSION_FLASH is present not only in the Flash
    // plugin. This permission is also present in plugins added from the cmdline
    // and so will be also present for "PPAPI Tests" plugin used for
    // OutOfProcessPPAPITest.URLLoaderTrusted and related tests.
    //
    // TODO(lukasza, laforge): https://crbug.com/702995: Remove the code below
    // once Flash support is removed from Chromium (probably around 2020 - see
    // https://www.chromium.org/flash-roadmap).
    RenderProcessHostImpl::AddCorbExceptionForPlugin(render_process_id);
  } else if (info->permissions & ppapi::PERMISSION_PDF) {
    // We want to limit ability to bypass |request_initiator_site_lock| to
    // trustworthy renderers.  PDF plugin is okay, because it is always hosted
    // by the PDF extension (mhjfbmdgcfjbbpaeojofohoefgiehjai) or
    // chrome://print, both of which we assume are trustworthy (the extension
    // process can also host other extensions, but this is okay).
    //
    // The CHECKs below help verify that |render_process_id| does not host
    // web-controlled content.  This is a defense-in-depth for verifying that
    // ShouldAllowPluginCreation called above is doing the right thing.
    auto* policy = ChildProcessSecurityPolicyImpl::GetInstance();
    GURL renderer_lock = policy->GetOriginLock(render_process_id);
    CHECK(!renderer_lock.SchemeIsHTTPOrHTTPS());
    CHECK(embedder_origin.scheme() != url::kHttpScheme);
    CHECK(embedder_origin.scheme() != url::kHttpsScheme);
    CHECK(!embedder_origin.opaque());

    // In some scenarios, the PDF plugin can issue fetch requests that will need
    // to be proxied by |render_process_id| - such proxying needs to bypass
    // CORB. See also https://crbug.com/1027173.
    //
    // TODO(lukasza, kmoon): https://crbug.com/702993: Remove the code here once
    // PDF support doesn't depend on PPAPI anymore.
    DCHECK(origin_lock.has_value());
    RenderProcessHostImpl::AddAllowedRequestInitiatorForPlugin(
        render_process_id, origin_lock.value());
  }

  PpapiPluginProcessHost* plugin_host =
      FindPpapiPluginProcess(plugin_path, profile_data_directory, origin_lock);
  if (plugin_host)
    return plugin_host;

  // Record when PPAPI Flash process is started for the first time.
  static bool counted = false;
  if (!counted && info->name == kFlashPluginName) {
    counted = true;
    UMA_HISTOGRAM_ENUMERATION("Plugin.FlashUsage",
                              START_PPAPI_FLASH_AT_LEAST_ONCE,
                              FLASH_USAGE_ENUM_COUNT);
  }

  // Avoid fork bomb.
  if (origin_lock.has_value() && CountPpapiPluginProcessesForProfile(
                                     plugin_path, profile_data_directory) >=
                                     max_ppapi_processes_per_profile_) {
    return nullptr;
  }

  // This plugin isn't loaded by any plugin process, so create a new process.
  plugin_host = PpapiPluginProcessHost::CreatePluginHost(
      *info, profile_data_directory, origin_lock);
  if (!plugin_host) {
    VLOG(1) << "Unable to create ppapi plugin process for: "
            << plugin_path.MaybeAsASCII();
  }

  return plugin_host;
}

PpapiPluginProcessHost* PluginServiceImpl::FindOrStartPpapiBrokerProcess(
    int render_process_id,
    const base::FilePath& plugin_path) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);

  if (filter_ && !filter_->CanLoadPlugin(render_process_id, plugin_path))
    return nullptr;

  PpapiPluginProcessHost* plugin_host = FindPpapiBrokerProcess(plugin_path);
  if (plugin_host)
    return plugin_host;

  // Validate that the plugin is actually registered.
  const PepperPluginInfo* info = GetRegisteredPpapiPluginInfo(plugin_path);
  if (!info)
    return nullptr;

  DCHECK(info->is_out_of_process);

  // This broker isn't loaded by any broker process, so create a new process.
  return PpapiPluginProcessHost::CreateBrokerHost(*info);
}

#if defined(USE_UNIONTECH_NPAPI)
void PluginServiceImpl::OpenChannelToNpapiPlugin(
    int render_process_id,
    int render_frame_id,
    const GURL& url,
    const GURL& page_url,
    const std::string& mime_type,
    PluginProcessHost::Client* client) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);
  pending_plugin_clients_.insert(client);

  // Make sure plugins are loaded if necessary.
  PluginServiceFilterParams params = {
    render_process_id,
    render_frame_id,
    page_url,
    client->GetResourceContext()
  };
  LOG(INFO) << "---- [NPAPI] PluginServiceImpl::OpenChannelToNpapiPlugin";
  LOG(INFO) << "---- [NPAPI] PluginServiceImpl::OpenChannelToNpapiPlugin render_process_id" << render_process_id;
  LOG(INFO) << "---- [NPAPI] PluginServiceImpl::OpenChannelToNpapiPlugin render_frame_id" << render_frame_id;
  LOG(INFO) << "---- [NPAPI] PluginServiceImpl::OpenChannelToNpapiPlugin mime_type" << mime_type << " url:" << url;
  GetPlugins(base::Bind(
      &PluginServiceImpl::ForwardGetAllowedPluginForOpenChannelToPlugin,
      base::Unretained(this), params, url, mime_type, client));
}
#endif

void PluginServiceImpl::OpenChannelToPpapiPlugin(
    int render_process_id,
    const url::Origin& embedder_origin,
    const base::FilePath& plugin_path,
    const base::FilePath& profile_data_directory,
    const base::Optional<url::Origin>& origin_lock,
    PpapiPluginProcessHost::PluginClient* client) {
  PpapiPluginProcessHost* plugin_host = FindOrStartPpapiPluginProcess(
      render_process_id, embedder_origin, plugin_path, profile_data_directory,
      origin_lock);
  if (plugin_host) {
    plugin_host->OpenChannelToPlugin(client);
  } else {
    // Send error.
    client->OnPpapiChannelOpened(IPC::ChannelHandle(), base::kNullProcessId, 0);
  }
}

void PluginServiceImpl::OpenChannelToPpapiBroker(
    int render_process_id,
    int render_frame_id,
    const base::FilePath& path,
    PpapiPluginProcessHost::BrokerClient* client) {
  base::PostTask(FROM_HERE, {BrowserThread::UI},
                 base::BindOnce(&PluginServiceImpl::RecordBrokerUsage,
                                render_process_id, render_frame_id));

  PpapiPluginProcessHost* plugin_host = FindOrStartPpapiBrokerProcess(
      render_process_id, path);
  if (plugin_host) {
    plugin_host->OpenChannelToPlugin(client);
  } else {
    // Send error.
    client->OnPpapiChannelOpened(IPC::ChannelHandle(), base::kNullProcessId, 0);
  }
}

#if defined(USE_UNIONTECH_NPAPI)
void PluginServiceImpl::CancelOpenChannelToNpapiPlugin(
    PluginProcessHost::Client* client) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);
  pending_plugin_clients_.erase(client);
}

void PluginServiceImpl::ForwardGetAllowedPluginForOpenChannelToPlugin(
    const PluginServiceFilterParams& params,
    const GURL& url,
    const std::string& mime_type,
    PluginProcessHost::Client* client,
    const std::vector<WebPluginInfo>&) {
  GetAllowedPluginForOpenChannelToPlugin(
      params.render_process_id, params.render_frame_id, url, params.page_url,
      mime_type, client, params.resource_context);
}

void PluginServiceImpl::GetAllowedPluginForOpenChannelToPlugin(
    int render_process_id,
    int render_frame_id,
    const GURL& url,
    const GURL& page_url,
    const std::string& mime_type,
    PluginProcessHost::Client* client,
    ResourceContext* resource_context) {
  WebPluginInfo info;
  bool allow_wildcard = true;
  bool found = GetPluginInfo(
      render_process_id, render_frame_id,
      url, url::Origin::Create(page_url), mime_type, allow_wildcard,
      NULL, &info, NULL);
  base::FilePath plugin_path;
  if (found) {
    plugin_path = info.path;
    LOG(INFO) << "--- [NPAPI] PluginServiceImpl::GetAllowedPluginForOpenChannelToPlugin found:" << plugin_path.MaybeAsASCII();
  }

  // Now we jump back to the IO thread to finish opening the channel.
  LOG(INFO) << "--- [NPAPI] PluginServiceImpl::GetAllowedPluginForOpenChannelToPlugin ---";
  base::PostTask(FROM_HERE, {BrowserThread::IO},
      base::BindOnce(&PluginServiceImpl::FinishOpenChannelToPlugin,
                 base::Unretained(this),
                 render_process_id,
                 plugin_path,
                 client));
  if (filter_) {
    DCHECK_EQ(WebPluginInfo::PLUGIN_TYPE_NPAPI, info.type);
    filter_->NPAPIPluginLoaded(render_process_id, render_frame_id, mime_type,
                              info);
    LOG(ERROR) << "--- [TODO] PluginServiceImpl::GetAllowedPluginForOpenChannelToPlugin 3---";
  }
}

void PluginServiceImpl::FinishOpenChannelToPlugin(
    int render_process_id,
    const base::FilePath& plugin_path,
    PluginProcessHost::Client* client) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);

  // Make sure it hasn't been canceled yet.
  // if (!ContainsKey(pending_plugin_clients_, client))
  std::set<PluginProcessHost::Client*>::iterator it;
  it = pending_plugin_clients_.find(client);
  if(it == pending_plugin_clients_.end())
    return;
  pending_plugin_clients_.erase(client);

  PluginProcessHost* plugin_host = FindOrStartNpapiPluginProcess(
      render_process_id, plugin_path);
  if (plugin_host) {
    client->OnFoundPluginProcessHost(plugin_host);
    plugin_host->OpenChannelToPlugin(client);
  } else {
    client->OnError();
  }
}
#endif

bool PluginServiceImpl::GetPluginInfoArray(
    const GURL& url,
    const std::string& mime_type,
    bool allow_wildcard,
    std::vector<WebPluginInfo>* plugins,
    std::vector<std::string>* actual_mime_types) {
  bool use_stale = false;
  PluginList::Singleton()->GetPluginInfoArray(
#if defined(USE_UNIONTECH_NPAPI)
      url, mime_type, allow_wildcard, &use_stale, NPAPIPluginsSupported(),
      plugins, actual_mime_types);
#else
      url, mime_type, allow_wildcard, &use_stale, plugins, actual_mime_types);
#endif
  return use_stale;
}

bool PluginServiceImpl::GetPluginInfo(int render_process_id,
                                      int render_frame_id,
                                      const GURL& url,
                                      const url::Origin& main_frame_origin,
                                      const std::string& mime_type,
                                      bool allow_wildcard,
                                      bool* is_stale,
                                      WebPluginInfo* info,
                                      std::string* actual_mime_type) {
  //DCHECK_CURRENTLY_ON(BrowserThread::UI);
  std::vector<WebPluginInfo> plugins;
  std::vector<std::string> mime_types;
  bool stale = GetPluginInfoArray(
      url, mime_type, allow_wildcard, &plugins, &mime_types);
  if (is_stale)
    *is_stale = stale;

  for (size_t i = 0; i < plugins.size(); ++i) {
    if (!filter_ ||
        filter_->IsPluginAvailable(render_process_id, render_frame_id, url,
                                   main_frame_origin, &plugins[i])) {
      *info = plugins[i];
      if (actual_mime_type)
        *actual_mime_type = mime_types[i];
      return true;
    }
  }
  return false;
}

bool PluginServiceImpl::GetPluginInfoByPath(const base::FilePath& plugin_path,
                                            WebPluginInfo* info) {
  std::vector<WebPluginInfo> plugins;
  PluginList::Singleton()->GetPluginsNoRefresh(&plugins);

  for (const WebPluginInfo& plugin : plugins) {
    if (plugin.path == plugin_path) {
      *info = plugin;
      return true;
    }
  }

  return false;
}

base::string16 PluginServiceImpl::GetPluginDisplayNameByPath(
    const base::FilePath& path) {
  base::string16 plugin_name = path.LossyDisplayName();
  WebPluginInfo info;
  if (PluginService::GetInstance()->GetPluginInfoByPath(path, &info) &&
      !info.name.empty()) {
    plugin_name = info.name;
#if defined(OS_MACOSX)
    // Many plugins on the Mac have .plugin in the actual name, which looks
    // terrible, so look for that and strip it off if present.
    static const char kPluginExtension[] = ".plugin";
    if (base::EndsWith(plugin_name, base::ASCIIToUTF16(kPluginExtension),
                       base::CompareCase::SENSITIVE))
      plugin_name.erase(plugin_name.length() - strlen(kPluginExtension));
#endif  // defined(OS_MACOSX)
  }
  return plugin_name;
}

void PluginServiceImpl::GetPlugins(GetPluginsCallback callback) {
  plugin_list_sequence_checker_.DetachFromSequence();
  base::PostTaskAndReplyWithResult(
      plugin_list_task_runner_.get(), FROM_HERE, base::BindOnce([]() {
        std::vector<WebPluginInfo> plugins;
#if defined(USE_UNIONTECH_NPAPI)
        PluginList::Singleton()->GetPlugins(&plugins,
            PluginServiceImpl::GetInstance()->NPAPIPluginsSupported());
#else
        PluginList::Singleton()->GetPlugins(&plugins);
#endif
        return plugins;
      }),
      std::move(callback));
}

void PluginServiceImpl::RegisterPepperPlugins() {
  ComputePepperPluginList(&ppapi_plugins_);
  for (const auto& plugin : ppapi_plugins_)
    RegisterInternalPlugin(plugin.ToWebPluginInfo(), /*add_at_beginning=*/true);
}

// There should generally be very few plugins so a brute-force search is fine.
const PepperPluginInfo* PluginServiceImpl::GetRegisteredPpapiPluginInfo(
    const base::FilePath& plugin_path) {
  for (auto& plugin : ppapi_plugins_) {
    if (plugin.path == plugin_path)
      return &plugin;
  }

  // We did not find the plugin in our list. But wait! the plugin can also
  // be a latecomer, as it happens with pepper flash. This information
  // can be obtained from the PluginList singleton and we can use it to
  // construct it and add it to the list. This same deal needs to be done
  // in the renderer side in PepperPluginRegistry.
  WebPluginInfo webplugin_info;
  if (!GetPluginInfoByPath(plugin_path, &webplugin_info))
    return nullptr;
  PepperPluginInfo new_pepper_info;
  if (!MakePepperPluginInfo(webplugin_info, &new_pepper_info))
    return nullptr;
  ppapi_plugins_.push_back(new_pepper_info);
  return &ppapi_plugins_.back();
}

void PluginServiceImpl::SetFilter(PluginServiceFilter* filter) {
  filter_ = filter;
}

PluginServiceFilter* PluginServiceImpl::GetFilter() {
  return filter_;
}

void PluginServiceImpl::ForcePluginShutdown(const base::FilePath& plugin_path) {
  if (!BrowserThread::CurrentlyOn(BrowserThread::IO)) {
    LOG(ERROR) << " ---- [TODO]PluginServiceImpl::ForcePluginShutdown ----";
    // BrowserThread::PostTask(
    //    BrowserThread::IO, FROM_HERE,
    //    base::Bind(&PluginServiceImpl::ForcePluginShutdown,
    //               base::Unretained(this), plugin_path));
    base::PostTask(
      FROM_HERE, {BrowserThread::IO},
       base::Bind(&PluginServiceImpl::ForcePluginShutdown,
                  base::Unretained(this), plugin_path));               
    return;
  }

  PluginProcessHost* plugin = FindNpapiPluginProcess(plugin_path);
  if (plugin)
    plugin->ForceShutdown();
}

static const unsigned int kMaxCrashesPerInterval = 3;
static const unsigned int kCrashesInterval = 120;

void PluginServiceImpl::RegisterPluginCrash(const base::FilePath& path) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);
  auto i = crash_times_.find(path);
  if (i == crash_times_.end()) {
    crash_times_[path] = std::vector<base::Time>();
    i = crash_times_.find(path);
  }
  if (i->second.size() == kMaxCrashesPerInterval) {
    i->second.erase(i->second.begin());
  }
  base::Time time = base::Time::Now();
  i->second.push_back(time);
}

bool PluginServiceImpl::IsPluginUnstable(const base::FilePath& path) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  std::map<base::FilePath, std::vector<base::Time> >::const_iterator i =
      crash_times_.find(path);
  if (i == crash_times_.end()) {
    return false;
  }
  if (i->second.size() != kMaxCrashesPerInterval) {
    return false;
  }
  base::TimeDelta delta = base::Time::Now() - i->second[0];
  return delta.InSeconds() <= kCrashesInterval;
}

void PluginServiceImpl::RefreshPlugins() {
  PluginList::Singleton()->RefreshPlugins();
}

#if defined(USE_UNIONTECH_NPAPI)
void PluginServiceImpl::AddExtraPluginPath(const base::FilePath& path) {
  if (!NPAPIPluginsSupported()) {
    // TODO(jam): remove and just have CHECK once we're sure this doesn't get
    // triggered.
    DVLOG(0) << "NPAPI plugins not supported";
    return;
  }
  PluginList::Singleton()->AddExtraPluginPath(path);
}

void PluginServiceImpl::RemoveExtraPluginPath(const base::FilePath& path) {
  PluginList::Singleton()->RemoveExtraPluginPath(path);
}

void PluginServiceImpl::AddExtraPluginDir(const base::FilePath& path) {
  PluginList::Singleton()->AddExtraPluginDir(path);
}
#endif

void PluginServiceImpl::RegisterInternalPlugin(
    const WebPluginInfo& info,
    bool add_at_beginning) {
#if defined(USE_UNIONTECH_NPAPI)
  // Internal plugins should never be NPAPI.
  CHECK_NE(info.type, WebPluginInfo::PLUGIN_TYPE_NPAPI);
  if (info.type == WebPluginInfo::PLUGIN_TYPE_NPAPI) {
    DVLOG(0) << "Don't register NPAPI plugins when they're not supported";
    //return;
  }
#endif
  PluginList::Singleton()->RegisterInternalPlugin(info, add_at_beginning);
}

void PluginServiceImpl::UnregisterInternalPlugin(const base::FilePath& path) {
  PluginList::Singleton()->UnregisterInternalPlugin(path);
}

void PluginServiceImpl::GetInternalPlugins(
    std::vector<WebPluginInfo>* plugins) {
  PluginList::Singleton()->GetInternalPlugins(plugins);
}

bool PluginServiceImpl::PpapiDevChannelSupported(
    BrowserContext* browser_context,
    const GURL& document_url) {
  return GetContentClient()->browser()->IsPluginAllowedToUseDevChannelAPIs(
      browser_context, document_url);
}

#if defined(OS_WIN)
void PluginServiceImpl::OnKeyChanged(base::win::RegKey* key) {
  key->StartWatching(base::Bind(&PluginServiceImpl::OnKeyChanged,
                                base::Unretained(this),
                                base::Unretained(key)));

  PluginList::Singleton()->RefreshPlugins();
  PurgePluginListCache(NULL, false);
}
#endif  // defined(OS_WIN)

#if defined(OS_POSIX) && !defined(OS_OPENBSD) && !defined(OS_ANDROID)
// static
void PluginServiceImpl::RegisterFilePathWatcher(FilePathWatcher* watcher,
                                                const base::FilePath& path) {
  bool result = watcher->Watch(path, false,
                               base::Bind(&NotifyPluginDirChanged));
  DCHECK(result);
}
#endif

#if 0
void PluginServiceImpl::ForcePluginShutdown(const base::FilePath& plugin_path) {
  if (!BrowserThread::CurrentlyOn(BrowserThread::IO)) {
    BrowserThread::PostTask(
        BrowserThread::IO, FROM_HERE,
        base::Bind(&PluginServiceImpl::ForcePluginShutdown,
                   base::Unretained(this), plugin_path));
    return;
  }

  PluginProcessHost* plugin = FindNpapiPluginProcess(plugin_path);
  if (plugin)
    plugin->ForceShutdown();
}
#endif

bool PluginServiceImpl::NPAPIPluginsSupported() {
  if (npapi_plugins_enabled_)
    return true;

  static bool command_line_checked = false;
  if (!command_line_checked) {
#if defined(OS_WIN) || defined(OS_MACOSX)
  npapi_plugins_enabled_ = GetContentClient()->browser()->IsNPAPIEnabled();
#if defined(OS_WIN)
  // NPAPI plugins don't play well with Win32k renderer lockdown.
  if (npapi_plugins_enabled_)
    DisableWin32kRendererLockdown();
#endif
  NPAPIPluginStatus status =
      npapi_plugins_enabled_ ? NPAPI_STATUS_ENABLED : NPAPI_STATUS_DISABLED;
#else
  const base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
  npapi_plugins_enabled_ = !command_line->HasSwitch(switches::kDisableNpapi);
  NPAPIPluginStatus status = npapi_plugins_enabled_ ? NPAPI_STATUS_ENABLED : NPAPI_STATUS_DISABLED;
#endif
  UMA_HISTOGRAM_ENUMERATION("Plugin.NPAPIStatus", status,
                            NPAPI_STATUS_ENUM_COUNT);
  }
  return npapi_plugins_enabled_;
}

void PluginServiceImpl::EnableNpapiPlugins() {
#if defined(OS_WIN)
  DisableWin32kRendererLockdown();
#endif
  npapi_plugins_enabled_ = true;
  RefreshPlugins();
  LOG(ERROR) << "--- [TODO]PluginServiceImpl::EnableNpapiPlugins ---";
  // BrowserThread::PostTask(
  //     BrowserThread::UI, FROM_HERE,
  //     base::Bind(&PluginService::PurgePluginListCache,
  //               static_cast<BrowserContext*>(NULL), false));
  base::PostTask(
       FROM_HERE,{BrowserThread::UI},
      base::Bind(&PluginService::PurgePluginListCache,
                static_cast<BrowserContext*>(NULL), false));                
}

#if defined(OS_MACOSX)
void PluginServiceImpl::AppActivated() {
  BrowserThread::PostTask(BrowserThread::IO, FROM_HERE,
                          base::Bind(&NotifyPluginsOfActivation));
}
#endif

}  // namespace content
