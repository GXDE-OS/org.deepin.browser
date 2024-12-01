// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/plugin_process_host.h"

#if defined(OS_WIN)
#include <windows.h>
#elif defined(OS_POSIX)
#include <utility>  // for pair<>
#endif

#include <vector>
//#define NPPLUGIN_RESOURCE_SAVE_2_DISK_FOR_TEST
#if defined(NPPLUGIN_RESOURCE_SAVE_2_DISK_FOR_TEST)
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "chrome/common/chrome_paths.h"
#endif
#include "base/base_switches.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/task/task_traits.h"
#include "base/logging.h"
#include "base/metrics/histogram.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/lock.h"
#include "base/task/post_task.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/net/system_network_context_manager.h"
#include "components/tracing/common/tracing_switches.h"
#include "content/browser/browser_child_process_host_impl.h"
#include "content/browser/child_process_security_policy_impl.h"
#include "content/browser/blob_storage/chrome_blob_storage_context.h"
#include "content/browser/gpu/gpu_data_manager_impl.h"
#include "content/browser/loader/resource_message_filter.h"
#include "content/browser/loader/resource_requester_info.h"
#include "content/browser/loader/url_loader_factory_impl.h"
#include "content/browser/plugin_service_impl.h"
#include "content/browser/storage_partition_impl.h"
#include "content/child/plugin_messages.h"
#include "content/child/request_info.h"
#include "content/common/child_process_host_impl.h"
#include "content/common/plugin_process_messages.h"
#include "content/common/resource_messages.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/content_browser_client.h"
#include "content/public/browser/notification_types.h"
#include "content/public/browser/plugin_service.h"
#include "content/public/browser/resource_context.h"
#include "content/public/common/content_client.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/process_type.h"
#include "content/public/common/sandboxed_process_launcher_delegate.h"
#include "content/public/common/service_manager_connection.h"
#include "content/public/common/service_names.mojom.h"
#include "content/renderer/loader/request_extra_data.h"
#include "content/browser/loader/file_url_loader_factory.h"
#include "content/public/browser/shared_cors_origin_access_list.h"
#include "mojo/core/embedder/embedder.h"
#include "net/base/load_flags.h"
#include "net/url_request/url_request_context_getter.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "services/network/cors/cors_url_loader_factory.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/sandbox/sandbox_type.h"
#include "services/network/resource_scheduler/resource_scheduler_client.h"
#include "services/service_manager/sandbox/switches.h"
#include "services/network/public/cpp/constants.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "ui/base/ui_base_switches.h"
#include "ui/display/display_switches.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/gl/gl_switches.h"

namespace content {

namespace {

const size_t kIPCPluginResourceDataMaxSizeByMB = 100; // MB

base::LazyInstance<std::map<base::ProcessId, WebPluginInfo> >::Leaky
    g_process_webplugin_info = LAZY_INSTANCE_INITIALIZER;
base::LazyInstance<base::Lock>::Leaky
    g_process_webplugin_info_lock = LAZY_INSTANCE_INITIALIZER;

const net::NetworkTrafficAnnotationTag kNavigationUrlLoaderTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("plugin_navigation_url_loader", R"(
      semantics {
        sender: "Navigation URL Loader"
        description:
          "This request is issued by a main frame navigation to fetch the "
          "content of the page that is being navigated to."
        trigger:
          "Navigating Chrome (by clicking on a link, bookmark, history item, "
          "using session restore, etc)."
        data:
          "Arbitrary site-controlled data can be included in the URL, HTTP "
          "headers, and request body. Requests may include cookies and "
          "site-specific credentials."
        destination: WEBSITE
      }
      policy {
        cookies_allowed: YES
        cookies_store: "user"
        setting: "This feature cannot be disabled."
        chrome_policy {
          URLBlacklist {
            URLBlacklist: { entries: '*' }
          }
        }
        chrome_policy {
          URLWhitelist {
            URLWhitelist { }
          }
        }
      }
      comments:
        "Chrome would be unable to navigate to websites without this type of "
        "request. Using either URLBlacklist or URLWhitelist policies (or a "
        "combination of both) limits the scope of these requests."
      )");

std::unique_ptr<network::ResourceRequest> CreateRequest(
    const RequestInfo& request_info,
    network::ResourceRequestBody* request_body,
    url::Origin& frame_origin) {
  std::unique_ptr<network::ResourceRequest> request(
      new network::ResourceRequest);
  request->method = request_info.method;
  request->url = request_info.url;
  request->site_for_cookies = net::SiteForCookies::FromUrl(request_info.first_party_for_cookies);
  request->request_initiator = request_info.request_initiator;
  request->referrer = request_info.referrer.url;
  request->referrer_policy = Referrer::ReferrerPolicyForUrlRequest(request_info.referrer.policy);
  request->headers.AddHeadersFromString(request_info.headers);
  request->headers.SetHeaderIfMissing(net::HttpRequestHeaders::kAccept, network::kDefaultAcceptHeaderValue);
  request->load_flags = request_info.load_flags;
  //request->plugin_child_id = request_info.requestor_pid;
  //request->resource_type = request_info.request_type;
  request->priority = request_info.priority;
  //request->request_context = request_info.request_context;
  //request->appcache_host_id = request_info.appcache_host_id;
  //request->allow_download = request_info.download_to_file;
  request->has_user_gesture = request_info.has_user_gesture;
  request->skip_service_worker = true;
  request->should_reset_appcache = request_info.should_reset_appcache;
  request->mode = request_info.fetch_request_mode;
  request->credentials_mode = request_info.fetch_credentials_mode;
  request->redirect_mode = request_info.fetch_redirect_mode;
  //request->fetch_request_context_type = request_info.fetch_request_context_type;
  //request->fetch_frame_type = request_info.fetch_frame_type;
  request->enable_load_timing = request_info.enable_load_timing;
  request->enable_upload_progress = request_info.enable_upload_progress;
  request->do_not_prompt_for_login = request_info.do_not_prompt_for_login;
  request->report_raw_headers = request_info.report_raw_headers;
  request->previews_state = request_info.previews_state;

  if ((request_info.referrer.policy == network::mojom::ReferrerPolicy::kDefault ||
       request_info.referrer.policy ==
           network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade) &&
      request_info.referrer.url.SchemeIsCryptographic() &&
      !request_info.url.SchemeIsCryptographic()) {
    LOG(FATAL) << "Trying to send secure referrer for insecure request "
               << "without an appropriate referrer policy.\n"
               << "URL = " << request_info.url << "\n"
               << "Referrer = " << request_info.referrer.url;
  }

  //const RequestExtraData kEmptyData;
  //const RequestExtraData* extra_data;
  //if (request_info.extra_data)
    //extra_data = static_cast<RequestExtraData*>(request_info.extra_data);
  //else
    //extra_data = &kEmptyData;
  //request->render_frame_id = extra_data->render_frame_id();
  //request->is_main_frame = extra_data->is_main_frame();
  //request->allow_download = extra_data->allow_download();
  //request->transition_type = extra_data->transition_type();
  //request->service_worker_provider_id = extra_data->service_worker_provider_id();
  request->originated_from_service_worker = false;
  request->request_body = request_body;
  //request->resource_body_stream_url = request_info.resource_body_stream_url;
  //request->initiated_in_secure_context = false;

  return request;
}

}  // namespace

class PluginResourceLoaderClient : public network::mojom::URLLoaderClient {
 public:
  PluginResourceLoaderClient(
      size_t maximum_download_size,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      PluginResourceLoader* parent)
      : client_binding_(this),
        data_pipe_watcher_(FROM_HERE,
                           mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                           std::move(task_runner)),
        parent_(parent),
        status_(Status::kNotStarted),
        completed_(false),
        maximum_download_size_(maximum_download_size) {
        response_code_ = -1;
  }

  ~PluginResourceLoaderClient() override {
    if (status_ != Status::kClosed) {
      Cancel();
    }
  }

  void Start(
      int request_id,
      const network::ResourceRequest& request,
      std::unique_ptr<network::mojom::URLLoaderFactory> url_loader_factory,
      const net::NetworkTrafficAnnotationTag& annotation_tag,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    status_ = Status::kStarted;

    //network::mojom::URLLoaderClientPtr client;
    //client_binding_.Bind(mojo::MakeRequest(&client), std::move(task_runner));

#if 0
    url_loader_factory->CreateLoaderAndStart(
        mojo::MakeRequest(&loader_), 0, request_id,
        network::mojom::kURLLoadOptionNone, request, this.CreateRemote(),
        net::MutableNetworkTrafficAnnotationTag(annotation_tag));
#else
    url_loader_factory->CreateLoaderAndStart(
        url_loader_.BindNewPipeAndPassReceiver(), 0, request_id,
        network::mojom::kURLLoadOptionNone, request, client_receiver_.BindNewPipeAndPassRemote(),
        net::MutableNetworkTrafficAnnotationTag(annotation_tag));
#endif
  }

  void Cancel() {
    ClearReceivedDataToFail();
    completed_ = true;
    Close();
  }

  bool IsActive() const {
    return status_ == Status::kStarted || status_ == Status::kFetching ||
           status_ == Status::kClosed;
  }

 private:
  enum class Status {
    kNotStarted,  // Initial state.
    kStarted,     // Start() is called, but data pipe is not ready yet.
    kFetching,    // Fetching via data pipe.
    kClosed,      // Data pipe is already closed, but may not be completed yet.
    kCompleted,   // Final state.
  };

  void MayComplete() {
    DCHECK(IsActive()) << "status: " << static_cast<int>(status_);
    DCHECK_NE(Status::kCompleted, status_);

    if (status_ == Status::kFetching || !completed_)
      return;

    status_ = Status::kCompleted;
    //loader_.reset();
    url_loader_.reset();
    parent_->OnLoadComplete();

    PluginResourceLoader::Resource resource;
    resource.mime = mime_;
    resource.head = head_;
    resource.data = data_;
    resource.response_code = response_code_;
    parent_->OnFetchResourceComplete(resource);
  }

  void ClearReceivedDataToFail() {
    head_.clear();
    data_.clear();
    mime_.clear();
  }

  void ReadDataPipe() {
    DCHECK_EQ(Status::kFetching, status_);

    for (;;) {
      const void* data;
      uint32_t size;
      MojoResult result =
          data_pipe_->BeginReadData(&data, &size, MOJO_READ_DATA_FLAG_NONE);
      if (result == MOJO_RESULT_SHOULD_WAIT) {
        data_pipe_watcher_.ArmOrNotify();
        return;
      }

      if (result == MOJO_RESULT_FAILED_PRECONDITION) {
        // Complete to read the data pipe successfully.
        Close();
        return;
      }
      DCHECK_EQ(MOJO_RESULT_OK, result);  // Only program errors can fire.

      if (data_.size() + size > maximum_download_size_) {
        data_pipe_->EndReadData(size);
        Cancel();
        return;
      }

      data_.append(static_cast<const char*>(data), size);

      result = data_pipe_->EndReadData(size);
      DCHECK_EQ(MOJO_RESULT_OK, result);  // Only program errors can fire.
    }
  }

  void Close() {
    if (status_ == Status::kFetching) {
      data_pipe_watcher_.Cancel();
      data_pipe_.reset();
    }
    // Copy down this code
    status_ = Status::kClosed;
    MayComplete();
  }

  void OnDataPipeSignaled(MojoResult result,
                          const mojo::HandleSignalsState& state) {
    ReadDataPipe();
  }

  // network::mojom::URLLoaderClient overrides:
  void OnReceiveResponse(
      network::mojom::URLResponseHeadPtr response_head) override {
    DCHECK_EQ(Status::kStarted, status_);
    // Existing callers need URL and HTTP status code. URL is already set in
    // Start().
    response_ = std::move(response_head);
    if (response_->headers) {

      head_ = response_->headers->raw_headers();
      std::string m;
      if (response_->headers->GetMimeType(&m)) {
        mime_ = m;
      }

      response_code_ = response_->headers->response_code();
    }
  }
  void OnReceiveRedirect(
      const net::RedirectInfo& redirect_info,
      network::mojom::URLResponseHeadPtr response_head) override {
    DCHECK_EQ(Status::kStarted, status_);
    //loader_->FollowRedirect({}, {}, base::nullopt);
    url_loader_->FollowRedirect({}, {}, base::nullopt);
  }
  void OnUploadProgress(int64_t current_position,
                        int64_t total_size,
                        OnUploadProgressCallback ack_callback) override {}
  void OnReceiveCachedMetadata(mojo_base::BigBuffer data) override {}
  void OnTransferSizeUpdated(int32_t transfer_size_diff) override {}
  void OnStartLoadingResponseBody(
      mojo::ScopedDataPipeConsumerHandle body) override {
    DCHECK_EQ(Status::kStarted, status_);
    status_ = Status::kFetching;

    data_pipe_ = std::move(body);
    data_pipe_watcher_.Watch(
        data_pipe_.get(),
        MOJO_HANDLE_SIGNAL_READABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
        MOJO_WATCH_CONDITION_SATISFIED,
        base::BindRepeating(&PluginResourceLoaderClient::OnDataPipeSignaled,
                            base::Unretained(this)));
    ReadDataPipe();
  }
  void OnComplete(const network::URLLoaderCompletionStatus& status) override {
    // When Cancel() sets |complete_|, OnComplete() may be called.
    if (completed_)
      return;

    DCHECK(IsActive()) << "status: " << static_cast<int>(status_);
    if (status.error_code != net::OK) {
      ClearReceivedDataToFail();
      Close();
    }
    completed_ = true;
    MayComplete();
  }

 private:
  network::mojom::URLLoaderPtr loader_;
  mojo::Binding<network::mojom::URLLoaderClient> client_binding_;
  mojo::ScopedDataPipeConsumerHandle data_pipe_;
  mojo::SimpleWatcher data_pipe_watcher_;
  PluginResourceLoader* parent_;
  Status status_;

  // A flag to represent if OnComplete() is already called. |data_pipe_| can be
  // ready even after OnComplete() is called.
  bool completed_;

  // Maximum download size to be stored in |data_|.
  const size_t maximum_download_size_;

  // Received data to be passed to the |callback_|.
  std::string data_;
  std::string head_;
  std::string mime_;
  int response_code_;

  network::mojom::URLResponseHeadPtr response_;
  mojo::Receiver<network::mojom::URLLoaderClient> client_receiver_{this};
  mojo::Remote<network::mojom::URLLoader> url_loader_;

  DISALLOW_COPY_AND_ASSIGN(PluginResourceLoaderClient);
};

PluginResourceLoader::Resource::Resource() {
  request_id = 0;
  resource_id = 0;
  routing_id = 0;
  response_code = 0;
}

PluginResourceLoader::PluginResourceLoader(
    scoped_refptr<ResourceRequesterInfo> requester_info,
    int request_id, int resource_id, int routing_id,
    const network::ResourceRequest& request,
    scoped_refptr<base::SingleThreadTaskRunner> runner,
    PluginResourceLoaderDelegate* delegate,
    network::mojom::NetworkContext* network_context,
    BrowserContext* browser_context)
    : delegate_(delegate) 
    , request_id_(request_id)
    , resource_id_(resource_id)
    , routing_id_(routing_id)
    , browser_context_(browser_context) {}

PluginResourceLoader::PluginResourceLoader(
                      std::unique_ptr<network::ResourceRequest> resource_request,
                      network::mojom::URLLoaderFactory* url_loader_factory,
                      int request_id,
                      int resource_id,
                      int routing_id,
                      PluginResourceLoaderDelegate* delegate)
                      : delegate_(delegate)
                      , request_id_(request_id)
                      , resource_id_(resource_id)
                      , routing_id_(routing_id) {
  url_ = resource_request->url;

  LOG(INFO) << "[NPAPI] PluginResourceLoader REQUEST url=" << url_;

  simple_url_loader_ = network::SimpleURLLoader::Create(
        std::move(resource_request), net::NetworkTrafficAnnotationTag(kNavigationUrlLoaderTrafficAnnotation));

  simple_url_loader_->DownloadAsStream(url_loader_factory, this);

  SetTimeout(base::TimeDelta::FromMilliseconds(20 * 1000));
}

PluginResourceLoader::~PluginResourceLoader() {
  simple_url_loader_.reset();
}

void PluginResourceLoader::SetTimeout(const base::TimeDelta& timeout) {
  //DCHECK(client_);
  //DCHECK(client_->IsActive());
  DCHECK(!timeout_timer_.IsRunning());

  timeout_timer_.Start(FROM_HERE, timeout, this,
                       &PluginResourceLoader::OnTimeout);
}

void PluginResourceLoader::CancelRequest() {
  //DCHECK(client_);
  //DCHECK(client_->IsActive());
  //client_->Cancel();
}

void PluginResourceLoader::OnFetchResourceComplete(Resource& resource) {
  if (request_id_ > 0) {
    if (-1 == resource.response_code) {
      if (resource.data.size() > 0) {
        if (url_.SchemeIs("file")) {
          resource.response_code = 10001;
        }
      }
    }

    resource.request_id = request_id_;
    resource.resource_id = resource_id_;
    resource.routing_id = routing_id_;

    request_id_ = 0;

    resource_ = resource;

    delay_task_.Start(FROM_HERE, base::TimeDelta::FromMilliseconds(50), this,
                      &PluginResourceLoader::OnReleaseResource);
  }
}

void PluginResourceLoader::OnDataReceived(base::StringPiece string_piece, base::OnceClosure resume)
{
  if (data_.size() + string_piece.length() > kIPCPluginResourceDataMaxSizeByMB * 1024 * 1024) {
    LOG(ERROR) << "[NPAPI] Plugin resource stream data is too large, just return";
    return;
  }

  data_.append(string_piece.as_string());
  std::move(resume).Run();
}

void PluginResourceLoader::OnComplete(bool success)
{
  int response_code = -1;
  if (simple_url_loader_->ResponseInfo() && simple_url_loader_->ResponseInfo()->headers) {
    response_code = simple_url_loader_->ResponseInfo()->headers->response_code();
    head_ = simple_url_loader_->ResponseInfo()->headers->raw_headers();
      std::string m;
      if (simple_url_loader_->ResponseInfo()->headers->GetMimeType(&m)) {
        mime_ = m;
      }
  }

  OnLoadComplete();

  Resource resource;
  resource.mime = mime_;
  resource.head = head_;
  resource.data = data_;
  resource.response_code = response_code;

  OnFetchResourceComplete(resource);
}

void PluginResourceLoader::OnRetry(base::OnceClosure start_retry)
{
  LOG(INFO) << "[NPAPI] PluginResourceLoader::OnRetry";
}

void PluginResourceLoader::OnLoadComplete() {
  timeout_timer_.Stop();
}

void PluginResourceLoader::OnTimeout() {
  //DCHECK(client_);
  //if (!client_)
  //  return;
  //DCHECK(client_->IsActive());
  //client_->Cancel();
}

void PluginResourceLoader::OnReleaseResource() {
  delegate_->OnFetchResourceComplete(resource_);
}

bool PluginProcessHost::GetWebPluginInfoFromPluginPid(base::ProcessId pid,
                                                      WebPluginInfo* info) {
  base::AutoLock lock(g_process_webplugin_info_lock.Get());
  if (!g_process_webplugin_info.Get().count(pid))
    return false;

  *info = g_process_webplugin_info.Get()[pid];
  return true;
}

// NOTE: changes to this class need to be reviewed by the security team.
class PluginSandboxedProcessLauncherDelegate
    : public SandboxedProcessLauncherDelegate {
 public:
  explicit PluginSandboxedProcessLauncherDelegate(ChildProcessHost* host)
#ifdef USE_NO_UNIONTECH_NPAPI_TAG
#if defined(OS_POSIX)
      : ipc_fd_(host->TakeClientFileDescriptor())
#endif  // OS_POSIX
#endif
  {}

  ~PluginSandboxedProcessLauncherDelegate() override {}

#if defined(USE_UNIONTECH_NPAPI) && defined(OS_LINUX)
  service_manager::SandboxType GetSandboxType() override {
    return service_manager::SandboxType::kNoSandbox;
  }

  service_manager::ZygoteHandle GetZygote() override {
    return service_manager::GetUnsandboxedZygote();
  }
#endif

#if defined(OS_POSIX)
  base::ScopedFD TakeIpcFd() { return std::move(ipc_fd_); }
#endif

 private:
#if defined(OS_POSIX)
  base::ScopedFD ipc_fd_;
#endif

  DISALLOW_COPY_AND_ASSIGN(PluginSandboxedProcessLauncherDelegate);
};

PluginProcessHost::PluginProcessHost()
    : pid_(base::kNullProcessId)
#if defined(OS_MACOSX)
    , plugin_cursor_visible_(true)
#endif
{
  process_.reset(new BrowserChildProcessHostImpl(PROCESS_TYPE_PLUGIN, this, ChildProcessHost::IpcMode::kNormal));
}

PluginProcessHost::~PluginProcessHost() {
  // Cancel all pending and sent requests.
  CancelRequests();

  {
    base::AutoLock lock(g_process_webplugin_info_lock.Get());
    g_process_webplugin_info.Get()[pid_] = info_;
  }
}

bool PluginProcessHost::Send(IPC::Message* message) {
  return process_->Send(message);
}

bool PluginProcessHost::Init(const WebPluginInfo& info) {
  info_ = info;
  process_->SetName(info_.name);

  process_->GetHost()->CreateChannelMojo();

  // Build command line for plugin. When we have a plugin launcher, we can't
  // allow "self" on linux and we need the real file path.
  const base::CommandLine& browser_command_line =
      *base::CommandLine::ForCurrentProcess();
  base::CommandLine::StringType plugin_launcher =
      browser_command_line.GetSwitchValueNative(switches::kPluginLauncher);

#if defined(OS_LINUX)
  int flags = plugin_launcher.empty() ? ChildProcessHost::CHILD_ALLOW_SELF :
                                        ChildProcessHost::CHILD_NORMAL;
#else
  int flags = ChildProcessHost::CHILD_NORMAL;
#endif

  base::FilePath exe_path = ChildProcessHost::GetChildPath(flags);
  if (exe_path.empty())
    return false;

  std::unique_ptr<base::CommandLine> cmd_line =
      std::make_unique<base::CommandLine>(exe_path);
  // Put the process type and plugin path first so they're easier to see
  // in process listings using native process management tools.
  cmd_line->AppendSwitchASCII(switches::kProcessType, switches::kPluginProcess);
  cmd_line->AppendSwitchPath(switches::kPluginPath, info.path);

  // Propagate the following switches to the plugin command line (along with
  // any associated values) if present in the browser command line
  static const char* const kSwitchNames[] = {
    switches::kDisableBreakpad,
    switches::kDisableDirectNPAPIRequests,
    switches::kFullMemoryCrashReport,
    switches::kLoggingLevel,
    switches::kLogPluginMessages,
    service_manager::switches::kNoSandbox,
    switches::kPluginStartupDialog,
    switches::kTraceConfigFile,
    switches::kTraceStartup,
    switches::kUseGL,
    switches::kForceDeviceScaleFactor,
#if defined(OS_MACOSX)
    switches::kDisableCoreAnimationPlugins,
    switches::kEnableSandboxLogging,
#endif
  };

  cmd_line->CopySwitchesFrom(browser_command_line, kSwitchNames,
                             sizeof(kSwitchNames)/sizeof(kSwitchNames[0]));

#if 0
  GpuDataManagerImpl::GetInstance()->AppendPluginCommandLine(cmd_line);
#endif

  // If specified, prepend a launcher program to the command line.
  if (!plugin_launcher.empty())
    cmd_line->PrependWrapper(plugin_launcher);

  std::string locale = GetContentClient()->browser()->GetApplicationLocale();
  if (!locale.empty()) {
    // Pass on the locale so the null plugin will use the right language in the
    // prompt to install the desired plugin.
    cmd_line->AppendSwitchASCII(switches::kLang, locale);
  }

  // The plugin needs to be shutdown gracefully, i.e. NP_Shutdown needs to be
  // called on the plugin. The plugin process exits when it receives the
  // OnChannelError notification indicating that the browser plugin channel has
  // been destroyed.
  bool terminate_on_shutdown = false;
  process_->Launch(
      std::make_unique<PluginSandboxedProcessLauncherDelegate>(process_->GetHost()),
      std::move(cmd_line),
      terminate_on_shutdown);

#if defined(USE_UNIONTECH_NPAPI) // For GrantCommitURL
  //ChildProcessSecurityPolicyImpl::GetInstance()->Add(process_->GetData().id, browser_context_);
#endif
  return true;
}

void PluginProcessHost::ForceShutdown() {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);
  Send(new PluginProcessMsg_NotifyRenderersOfPendingShutdown());
  process_->ForceShutdown();
}

bool PluginProcessHost::OnMessageReceived(const IPC::Message& msg) {
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(PluginProcessHost, msg)
    IPC_MESSAGE_HANDLER(PluginProcessHostMsg_ChannelCreated, OnChannelCreated)
    IPC_MESSAGE_HANDLER(PluginProcessHostMsg_ChannelDestroyed, OnChannelDestroyed)
    IPC_MESSAGE_HANDLER(PluginProcessMsg_CreateLoaderAndStart, OnCreateLoaderAndStart)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()

  return handled;
}

void PluginProcessHost::OnChannelConnected(int32_t peer_pid) {
  for (size_t i = 0; i < pending_requests_.size(); ++i) {
    RequestPluginChannel(pending_requests_[i]);
  }

  pending_requests_.clear();

  pid_ = peer_pid;
  {
    base::AutoLock lock(g_process_webplugin_info_lock.Get());
    g_process_webplugin_info.Get()[pid_] = info_;
  }
}

void PluginProcessHost::OnChannelError() {
  CancelRequests();
}

void PluginProcessHost::OnProcessCrashed(int exit_code) {
  PluginServiceImpl::GetInstance()->RegisterPluginCrash(info_.path);
}

void PluginProcessHost::CancelRequests() {
  for (size_t i = 0; i < pending_requests_.size(); ++i)
    pending_requests_[i]->OnError();
  pending_requests_.clear();

  while (!sent_requests_.empty()) {
    Client* client = sent_requests_.front();
    if (client)
      client->OnError();
    sent_requests_.pop_front();
  }
}

void PluginProcessHost::OpenChannelToPlugin(Client* client) {
#if defined(USE_UNIONTECH_NPAPI)
  if (client) {
    browser_context_ = client->GetBrowserContext();
  }

  base::PostTask(
      FROM_HERE, {BrowserThread::UI},
      base::BindOnce(&BrowserChildProcessHostImpl::NotifyProcessInstanceCreated,
                 std::ref(process_->GetData())));
#endif
  client->SetPluginInfo(info_);
  if (process_->GetHost()->IsChannelOpening()) {
    // The channel is already in the process of being opened.  Put
    // this "open channel" request into a queue of requests that will
    // be run once the channel is open.
    pending_requests_.push_back(client);
    return;
  }

  // We already have an open channel, send a request right away to plugin.
  RequestPluginChannel(client);
}

void PluginProcessHost::CancelPendingRequest(Client* client) {
  std::vector<Client*>::iterator it = pending_requests_.begin();
  while (it != pending_requests_.end()) {
    if (client == *it) {
      pending_requests_.erase(it);
      return;
    }
    ++it;
  }
  DCHECK(it != pending_requests_.end());
}

void PluginProcessHost::CancelSentRequest(Client* client) {
  std::list<Client*>::iterator it = sent_requests_.begin();
  while (it != sent_requests_.end()) {
    if (client == *it) {
      *it = NULL;
      return;
    }
    ++it;
  }
  DCHECK(it != sent_requests_.end());
}

void PluginProcessHost::RequestPluginChannel(Client* client) {
  // We can't send any sync messages from the browser because it might lead to
  // a hang.  However this async messages must be answered right away by the
  // plugin process (i.e. unblocks a Send() call like a sync message) otherwise
  // a deadlock can occur if the plugin creation request from the renderer is
  // a result of a sync message by the plugin process.
  PluginProcessMsg_CreateChannel* msg =
      new PluginProcessMsg_CreateChannel(
          client->ID(),
          client->OffTheRecord());
  msg->set_unblock(true);
  if (Send(msg)) {
    sent_requests_.push_back(client);
    client->OnSentPluginChannelRequest();
  } else {
    client->OnError();
  }
}

void PluginProcessHost::OnChannelCreated(
    const IPC::ChannelHandle& channel_handle) {
  Client* client = sent_requests_.front();

  if (client) {
    if (!resource_context_map_.count(client->ID())) {
      ResourceContextEntry entry;
      entry.ref_count = 0;
      entry.resource_context = client->GetResourceContext();
      resource_context_map_[client->ID()] = entry;
    }
    resource_context_map_[client->ID()].ref_count++;
    client->OnChannelOpened(channel_handle);
  }
  sent_requests_.pop_front();
}

void PluginProcessHost::OnChannelDestroyed(int renderer_id) {
  resource_context_map_[renderer_id].ref_count--;
  if (!resource_context_map_[renderer_id].ref_count)
    resource_context_map_.erase(renderer_id);
}

#if defined(USE_UNIONTECH_NPAPI)
void PluginProcessHost::PrepareToCreateLoaderAndStartOnUI(int plugin_process_id, int request_id) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);

  StoragePartitionImpl* storage_partition_impl =
      static_cast<StoragePartitionImpl*>(
          BrowserContext::GetDefaultStoragePartition(browser_context_));

  base::PostTask(
      FROM_HERE, {BrowserThread::IO},
      base::Bind(&PluginProcessHost::CreateLoaderAndStartOnIO,
                  base::Unretained(this),
                  request_id,
                  base::Passed(storage_partition_impl->GetURLLoaderFactoryForBrowserProcessIOThread())));
}

void PluginProcessHost::CreateLoaderAndStartOnIO(int request_id,
                                                 std::unique_ptr<network::PendingSharedURLLoaderFactory> pending_shared_url_loader_factory) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);
  PluginProcessMsg_CreateLoaderAndStart_ParamsMap::iterator result = params_map_.find(request_id);
  if (result == params_map_.end()) {
    DCHECK(false);
    return;
  }

  PluginProcessMsg_CreateLoaderAndStart_Params params = *(result->second.get());
  int plugin_child_id = process_->GetData().id;
  if (!ChildProcessSecurityPolicyImpl::GetInstance()->IsWebSafeScheme(params.url.scheme())) {
    ChildProcessSecurityPolicyImpl::GetInstance()->GrantCommitURL(plugin_child_id, params.url);
  }

  RequestInfo request_info;
  request_info.requestor_pid = plugin_child_id;
  request_info.method = params.method;
  request_info.headers = params.headers;
  request_info.url = params.url;
  request_info.first_party_for_cookies = params.first_party_for_cookies;
  request_info.referrer = Referrer(params.referrer, params.referrer_policy);
  request_info.load_flags = net::LOAD_NORMAL;
  //request_info.requestor_pid = params.plugin_child_id;
  request_info.request_type = content::ResourceType::kPluginResource;
  request_info.routing_id = params.routing_id;
  request_info.fetch_credentials_mode = network::mojom::CredentialsMode::kInclude;
  auto extra_data = base::MakeRefCounted<RequestExtraData>();
  extra_data->set_render_frame_id(params.render_frame_id);
  extra_data->set_is_main_frame(false);
  request_info.extra_data = std::move(extra_data);
  scoped_refptr<network::ResourceRequestBody> request_body = nullptr;
  if (!params.buffer.empty()) {
    request_body = new network::ResourceRequestBody;
    request_body->AppendBytes(&params.buffer[0], params.buffer.size());
  }

  url::Origin frame_origin;
  std::unique_ptr<network::ResourceRequest> request =
      CreateRequest(request_info, request_body.get(), frame_origin);

  scoped_refptr<base::SingleThreadTaskRunner> runner =
      base::ThreadTaskRunnerHandle::Get();

  shared_url_loader_factory_ = network::SharedURLLoaderFactory::Create(std::move(pending_shared_url_loader_factory));
  std::unique_ptr<PluginResourceLoader> plugin_resource_loader =
      std::make_unique<PluginResourceLoader>(std::move(request),
                                             shared_url_loader_factory_.get(),
                                             params.request_id,
                                             params.resource_id,
                                             params.routing_id,
                                             this);

  plugin_resource_loader_map_[params.request_id] = std::move(plugin_resource_loader);
}

#if defined(NPPLUGIN_RESOURCE_SAVE_2_DISK_FOR_TEST)
void SaveResource(const std::string& data, int resource_id) {
  base::FilePath path;
  if (base::PathService::Get(chrome::DIR_USER_DATA, &path)) {
    path = path.Append(base::NumberToString(resource_id));
    base::WriteFile(path, data.data(), data.size());
  }
}
#endif

void PluginProcessHost::OnFetchResourceComplete(const PluginResourceLoader::Resource& resource) {
  if (resource.request_id <= 0)
    return;
  PluginResourceLoaderMap::iterator result = plugin_resource_loader_map_.find(resource.request_id);
  if (result == plugin_resource_loader_map_.end() || resource.response_code == -1)
    return;

  PluginProcessMsg_ResourceFetched_Params params;

  params.routing_id = resource.routing_id;
  params.request_id = resource.request_id;
  params.resource_id = resource.resource_id;
  params.response_code = resource.response_code;
  params.mime = resource.mime;
  params.head = resource.head;
  params.data = resource.data;

#if defined(NPPLUGIN_RESOURCE_SAVE_2_DISK_FOR_TEST)
  base::ThreadPool::PostTask(
    FROM_HERE,  {base::MayBlock(), base::TaskPriority::USER_BLOCKING},
    base::BindOnce(&SaveResource, resource.data, resource.resource_id));
#endif

  Send(new PluginProcessMsg_ResourceFetched(params));
  plugin_resource_loader_map_.erase(resource.request_id);
}

void PluginProcessHost::OnCreateLoaderAndStart(
    const PluginProcessMsg_CreateLoaderAndStart_Params& params) {
  DCHECK(browser_context_);
  LOG(INFO) << "[NPAPI] PluginProcessHost::OnCreateLoaderAndStart";
  std::unique_ptr<PluginProcessMsg_CreateLoaderAndStart_Params> _params = std::make_unique<PluginProcessMsg_CreateLoaderAndStart_Params>(params);
  params_map_[params.request_id] = std::move(_params);
  base::PostTask(FROM_HERE, {BrowserThread::UI},
                 base::Bind(&PluginProcessHost::PrepareToCreateLoaderAndStartOnUI, base::Unretained(this), process_->GetData().id, params.request_id));
}
#endif

}  // namespace content
