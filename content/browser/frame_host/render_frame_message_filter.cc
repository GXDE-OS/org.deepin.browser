// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/frame_host/render_frame_message_filter.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/debug/alias.h"
#include "base/feature_list.h"
#include "base/macros.h"
#include "base/strings/string_util.h"
#include "base/syslog_logging.h"
#include "base/task/post_task.h"
#include "base/unguessable_token.h"
#include "build/build_config.h"
#include "content/browser/bad_message.h"
#include "content/browser/blob_storage/chrome_blob_storage_context.h"
#include "content/browser/child_process_security_policy_impl.h"
#include "content/browser/frame_host/ipc_utils.h"
#include "content/browser/frame_host/render_frame_host_impl.h"
#include "content/browser/renderer_host/render_widget_helper.h"
#include "content/browser/resource_context_impl.h"
#include "content/browser/storage_partition_impl.h"
#include "content/common/frame_messages.h"
#include "content/common/view_messages.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/storage_partition.h"
#include "content/public/common/content_client.h"
#include "content/public/common/content_constants.h"
#include "content/public/common/content_features.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "mojo/public/cpp/bindings/callback_helpers.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/system/message_pipe.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "ppapi/buildflags/buildflags.h"
#include "services/service_manager/public/mojom/interface_provider.mojom.h"
#include "storage/browser/blob/blob_storage_context.h"
#include "third_party/blink/public/common/frame/frame_owner_element_type.h"
#include "third_party/blink/public/common/frame/frame_policy.h"
#include "third_party/blink/public/mojom/frame/frame_owner_properties.mojom.h"
#include "third_party/blink/public/mojom/web_feature/web_feature.mojom.h"
#include "url/gurl.h"
#include "url/origin.h"

#if !defined(OS_MACOSX)
#include "third_party/khronos/GLES2/gl2.h"
#include "third_party/khronos/GLES2/gl2ext.h"
#endif

#if BUILDFLAG(ENABLE_PLUGINS)
#include "content/browser/plugin_service_impl.h"
#include "content/browser/ppapi_plugin_process_host.h"
#include "content/public/browser/plugin_service_filter.h"
#endif

namespace content {

namespace {

void CreateChildFrameOnUI(
    int process_id,
    int parent_routing_id,
    blink::WebTreeScopeType scope,
    const std::string& frame_name,
    const std::string& frame_unique_name,
    bool is_created_by_script,
    const base::UnguessableToken& devtools_frame_token,
    const blink::FramePolicy& frame_policy,
    const blink::mojom::FrameOwnerProperties& frame_owner_properties,
    blink::FrameOwnerElementType owner_type,
    int new_routing_id,
    mojo::ScopedMessagePipeHandle interface_provider_receiver_handle,
    mojo::ScopedMessagePipeHandle browser_interface_broker_handle) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  RenderFrameHostImpl* render_frame_host =
      RenderFrameHostImpl::FromID(process_id, parent_routing_id);
  // Handles the RenderFrameHost being deleted on the UI thread while
  // processing a subframe creation message.
  if (render_frame_host) {
    render_frame_host->OnCreateChildFrame(
        new_routing_id,
        mojo::PendingReceiver<service_manager::mojom::InterfaceProvider>(
            std::move(interface_provider_receiver_handle)),
        mojo::PendingReceiver<blink::mojom::BrowserInterfaceBroker>(
            std::move(browser_interface_broker_handle)),
        scope, frame_name, frame_unique_name, is_created_by_script,
        devtools_frame_token, frame_policy, frame_owner_properties, owner_type);
  }
}

// Common functionality for converting a sync renderer message to a callback
// function in the browser. Derive from this, create it on the heap when
// issuing your callback. When done, write your reply parameters into
// reply_msg(), and then call SendReplyAndDeleteThis().
class RenderMessageCompletionCallback {
 public:
  RenderMessageCompletionCallback(RenderFrameMessageFilter* filter,
                                  IPC::Message* reply_msg)
      : filter_(filter), reply_msg_(reply_msg) {}

  virtual ~RenderMessageCompletionCallback() {
    if (reply_msg_) {
      // If the owner of this class failed to call SendReplyAndDeleteThis(),
      // send an error reply to prevent the renderer from being hung.
      reply_msg_->set_reply_error();
      filter_->Send(reply_msg_);
    }
  }

  RenderFrameMessageFilter* filter() { return filter_.get(); }
  IPC::Message* reply_msg() { return reply_msg_; }

  void SendReplyAndDeleteThis() {
    filter_->Send(reply_msg_);
    reply_msg_ = nullptr;
    delete this;
  }

 private:
  scoped_refptr<RenderFrameMessageFilter> filter_;
  IPC::Message* reply_msg_;
};

}  // namespace

#if BUILDFLAG(ENABLE_PLUGINS)

class RenderFrameMessageFilter::OpenChannelToPpapiBrokerCallback
    : public PpapiPluginProcessHost::BrokerClient {
 public:
  OpenChannelToPpapiBrokerCallback(RenderFrameMessageFilter* filter,
                                   int routing_id)
      : filter_(filter), routing_id_(routing_id) {}

  ~OpenChannelToPpapiBrokerCallback() override {}

  void GetPpapiChannelInfo(base::ProcessHandle* renderer_handle,
                           int* renderer_id) override {
    // base::kNullProcessHandle indicates that the channel will be used by the
    // browser itself. Make sure we never output that value here.
    CHECK_NE(base::kNullProcessHandle, filter_->PeerHandle());
    *renderer_handle = filter_->PeerHandle();
    *renderer_id = filter_->render_process_id_;
  }

  void OnPpapiChannelOpened(const IPC::ChannelHandle& channel_handle,
                            base::ProcessId plugin_pid,
                            int /* plugin_child_id */) override {
    filter_->Send(new ViewMsg_PpapiBrokerChannelCreated(routing_id_, plugin_pid,
                                                        channel_handle));
    delete this;
  }

  bool Incognito() override { return filter_->incognito_; }

 private:
  scoped_refptr<RenderFrameMessageFilter> filter_;
  int routing_id_;
};

#if defined(USE_UNIONTECH_NPAPI)
class RenderFrameMessageFilter::OpenChannelToNpapiPluginCallback
    : public RenderMessageCompletionCallback,
      public PluginProcessHost::Client {
 public:
  OpenChannelToNpapiPluginCallback(RenderFrameMessageFilter* filter,
                                   ResourceContext* context,
                                   IPC::Message* reply_msg)
      : RenderMessageCompletionCallback(filter, reply_msg),
        context_(context),
        host_(nullptr),
        sent_plugin_channel_request_(false) {
  }

  int ID() override { return filter()->render_process_id_; }

  ResourceContext* GetResourceContext() override { return context_; }

  bool OffTheRecord() override {
    if (filter()->incognito_)
      return true;
    return false;
  }

  void SetPluginInfo(const WebPluginInfo& info) override { info_ = info; }

  void OnFoundPluginProcessHost(PluginProcessHost* host) override {
    DCHECK(host);
    host_ = host;
  }

  void OnSentPluginChannelRequest() override {
    sent_plugin_channel_request_ = true;
  }

  void OnChannelOpened(const IPC::ChannelHandle& handle) override {
    WriteReplyAndDeleteThis(handle);
  }

  void OnError() override { WriteReplyAndDeleteThis(IPC::ChannelHandle()); }

  PluginProcessHost* host() const {
    return host_;
  }

  void SetBrowserContext(BrowserContext* browser_context) {
    DCHECK(browser_context);
    browser_context_ = browser_context;
  }
  BrowserContext* GetBrowserContext() override {
    return browser_context_;
  }

  bool sent_plugin_channel_request() const {
    return sent_plugin_channel_request_;
  }

  void Cancel() {
    delete this;
  }

 private:
  void WriteReplyAndDeleteThis(const IPC::ChannelHandle& handle) {
    FrameHostMsg_OpenChannelToPlugin::WriteReplyParams(reply_msg(),
                                                       handle, info_);
    filter()->OnCompletedOpenChannelToNpapiPlugin(this);
    SendReplyAndDeleteThis();
  }

  ResourceContext* context_;
  WebPluginInfo info_;
  PluginProcessHost* host_;
  BrowserContext* browser_context_;
  bool sent_plugin_channel_request_;
};
#endif

class RenderFrameMessageFilter::OpenChannelToPpapiPluginCallback
    : public RenderMessageCompletionCallback,
      public PpapiPluginProcessHost::PluginClient {
 public:
  OpenChannelToPpapiPluginCallback(RenderFrameMessageFilter* filter,
                                   IPC::Message* reply_msg)
      : RenderMessageCompletionCallback(filter, reply_msg) {}

  void GetPpapiChannelInfo(base::ProcessHandle* renderer_handle,
                           int* renderer_id) override {
    // base::kNullProcessHandle indicates that the channel will be used by the
    // browser itself. Make sure we never output that value here.
    CHECK_NE(base::kNullProcessHandle, filter()->PeerHandle());
    *renderer_handle = filter()->PeerHandle();
    *renderer_id = filter()->render_process_id_;
  }

  void OnPpapiChannelOpened(const IPC::ChannelHandle& channel_handle,
                            base::ProcessId plugin_pid,
                            int plugin_child_id) override {
    FrameHostMsg_OpenChannelToPepperPlugin::WriteReplyParams(
        reply_msg(), channel_handle, plugin_pid, plugin_child_id);
    SendReplyAndDeleteThis();
  }

  bool Incognito() override { return filter()->incognito_; }
};

#endif  // ENABLE_PLUGINS

RenderFrameMessageFilter::RenderFrameMessageFilter(
    int render_process_id,
    PluginServiceImpl* plugin_service,
    BrowserContext* browser_context,
    StoragePartition* storage_partition,
    RenderWidgetHelper* render_widget_helper)
    : BrowserMessageFilter(FrameMsgStart),
#if BUILDFLAG(ENABLE_PLUGINS)
      plugin_service_(plugin_service),
#if defined(USE_UNIONTECH_NPAPI)
      browser_context_(browser_context),
#endif
      profile_data_directory_(storage_partition->GetPath()),
#endif  // ENABLE_PLUGINS
      resource_context_(browser_context->GetResourceContext()),
      render_widget_helper_(render_widget_helper),
      incognito_(browser_context->IsOffTheRecord()),
      render_process_id_(render_process_id) {
}

RenderFrameMessageFilter::~RenderFrameMessageFilter() {
  // This function should be called on the IO thread.
  DCHECK_CURRENTLY_ON(BrowserThread::IO);
#if defined(USE_UNIONTECH_NPAPI)
  DCHECK(plugin_host_clients_.empty());
#endif
}

#if defined(USE_UNIONTECH_NPAPI)
void RenderFrameMessageFilter::OnChannelClosing() {
  for (OpenChannelToNpapiPluginCallback* client : plugin_host_clients_) {
    if (client->host()) {
      if (client->sent_plugin_channel_request()) {
        client->host()->CancelSentRequest(client);
      } else {
        client->host()->CancelPendingRequest(client);
      }
    } else {
      plugin_service_->CancelOpenChannelToNpapiPlugin(client);
    }
    client->Cancel();
  }
  plugin_host_clients_.clear();
}
#endif

void RenderFrameMessageFilter::ClearResourceContext() {
  resource_context_ = nullptr;
}

bool RenderFrameMessageFilter::OnMessageReceived(const IPC::Message& message) {
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(RenderFrameMessageFilter, message)
    IPC_MESSAGE_HANDLER(FrameHostMsg_CreateChildFrame, OnCreateChildFrame)
#if BUILDFLAG(ENABLE_PLUGINS)
    IPC_MESSAGE_HANDLER_DELAY_REPLY(ViewHostMsg_GetPlugins, OnGetPlugins)
    IPC_MESSAGE_HANDLER(FrameHostMsg_GetPluginInfo, OnGetPluginInfo)
#if defined(USE_UNIONTECH_NPAPI)
    IPC_MESSAGE_HANDLER_DELAY_REPLY(FrameHostMsg_OpenChannelToPlugin,
                                    OnOpenChannelToPlugin)
#endif
    IPC_MESSAGE_HANDLER_DELAY_REPLY(FrameHostMsg_OpenChannelToPepperPlugin,
                                    OnOpenChannelToPepperPlugin)
    IPC_MESSAGE_HANDLER(FrameHostMsg_DidCreateOutOfProcessPepperInstance,
                        OnDidCreateOutOfProcessPepperInstance)
    IPC_MESSAGE_HANDLER(FrameHostMsg_DidDeleteOutOfProcessPepperInstance,
                        OnDidDeleteOutOfProcessPepperInstance)
    IPC_MESSAGE_HANDLER(FrameHostMsg_OpenChannelToPpapiBroker,
                        OnOpenChannelToPpapiBroker)
    IPC_MESSAGE_HANDLER(FrameHostMsg_PluginInstanceThrottleStateChange,
                        OnPluginInstanceThrottleStateChange)
#endif  // ENABLE_PLUGINS
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()

  return handled;
}

void RenderFrameMessageFilter::OnDestruct() const {
  BrowserThread::DeleteOnIOThread::Destruct(this);
}

void RenderFrameMessageFilter::OverrideThreadForMessage(
    const IPC::Message& message,
    BrowserThread::ID* thread) {
#if BUILDFLAG(ENABLE_PLUGINS)
  if (message.type() == FrameHostMsg_GetPluginInfo::ID)
    *thread = BrowserThread::UI;
#endif  // ENABLE_PLUGINS
}

void RenderFrameMessageFilter::OnCreateChildFrame(
    const FrameHostMsg_CreateChildFrame_Params& params,
    FrameHostMsg_CreateChildFrame_Params_Reply* params_reply) {
  params_reply->child_routing_id = render_widget_helper_->GetNextRoutingID();

  mojo::PendingRemote<service_manager::mojom::InterfaceProvider>
      interface_provider;
  auto interface_provider_receiver(
      interface_provider.InitWithNewPipeAndPassReceiver());
  params_reply->new_interface_provider =
      interface_provider.PassPipe().release();

  mojo::PendingRemote<blink::mojom::BrowserInterfaceBroker>
      browser_interface_broker;
  auto browser_interface_broker_receiver =
      browser_interface_broker.InitWithNewPipeAndPassReceiver();
  params_reply->browser_interface_broker_handle =
      browser_interface_broker.PassPipe().release();

  params_reply->devtools_frame_token = base::UnguessableToken::Create();

  base::PostTask(
      FROM_HERE, {BrowserThread::UI},
      base::BindOnce(
          &CreateChildFrameOnUI, render_process_id_, params.parent_routing_id,
          params.scope, params.frame_name, params.frame_unique_name,
          params.is_created_by_script, params_reply->devtools_frame_token,
          params.frame_policy, params.frame_owner_properties,
          params.frame_owner_element_type, params_reply->child_routing_id,
          interface_provider_receiver.PassPipe(),
          browser_interface_broker_receiver.PassPipe()));
}

#if BUILDFLAG(ENABLE_PLUGINS)

void RenderFrameMessageFilter::OnGetPluginInfo(
    int render_frame_id,
    const GURL& url,
    const url::Origin& main_frame_origin,
    const std::string& mime_type,
    bool* found,
    WebPluginInfo* info,
    std::string* actual_mime_type) {
  bool allow_wildcard = true;
  *found = plugin_service_->GetPluginInfo(
      render_process_id_, render_frame_id, url, main_frame_origin, mime_type,
      allow_wildcard, nullptr, info, actual_mime_type);
}

void RenderFrameMessageFilter::OnGetPlugins(
    bool refresh,
    IPC::Message* reply_msg) {
  LOG(INFO)<<"---- [TODO] RenderFrameMessageFilter::OnGetPlugins ----";
  const int kPluginsRefreshThresholdInSeconds = 3;
  // Don't refresh if the specified threshold has not been passed.  Note that
  // this check is performed before off-loading to the file thread.  The reason
  // we do this is that some pages tend to request that the list of plugins be
  // refreshed at an excessive rate.  This instigates disk scanning, as the list
  // is accumulated by doing multiple reads from disk.  This effect is
  // multiplied when we have several pages requesting this operation.
  if (refresh) {
    const base::TimeDelta threshold = base::TimeDelta::FromSeconds(
        kPluginsRefreshThresholdInSeconds);
    const base::TimeTicks now = base::TimeTicks::Now();
    if (now - last_plugin_refresh_time_ >= threshold) {
      // Only refresh if the threshold hasn't been exceeded yet.
      PluginServiceImpl::GetInstance()->RefreshPlugins();
      last_plugin_refresh_time_ = now;
    }
  }

  PluginServiceImpl::GetInstance()->GetPlugins(
      base::Bind(&RenderFrameMessageFilter::GetPluginsCallback, this, reply_msg));
}

void RenderFrameMessageFilter::GetPluginsCallback(
    IPC::Message* reply_msg,
    const std::vector<WebPluginInfo>& all_plugins) {
  LOG(INFO)<<"---- [TODO] RenderFrameMessageFilter::GetPluginsCallback ----";
  // Filter the plugin list.
  PluginServiceFilter* filter = PluginServiceImpl::GetInstance()->GetFilter();
  std::vector<WebPluginInfo> plugins;

  int child_process_id = -1;
  int routing_id = MSG_ROUTING_NONE;
  for (size_t i = 0; i < all_plugins.size(); ++i) {
    // Copy because the filter can mutate.
    WebPluginInfo plugin(all_plugins[i]);
    if (!filter || filter->IsPluginAvailable(child_process_id,
                                             routing_id,
                                             //resource_context_,
                                             GURL(),
                                             url::Origin(),
                                             &plugin)) {      
      plugins.push_back(plugin);
    }
  }

  ViewHostMsg_GetPlugins::WriteReplyParams(reply_msg, plugins);
  Send(reply_msg);
}

#if defined(USE_UNIONTECH_NPAPI)
void RenderFrameMessageFilter::OnOpenChannelToPlugin(
    int render_frame_id,
    const GURL& url,
    const GURL& policy_url,
    const std::string& mime_type,
    IPC::Message* reply_msg) {
  LOG(INFO) << "[NPAPI] Receive OnOpenChannelToPlugin Msg, url:" << policy_url;
  OpenChannelToNpapiPluginCallback* client =
      new OpenChannelToNpapiPluginCallback(this, resource_context_, reply_msg);
#if defined(USE_UNIONTECH_NPAPI)
  client->SetBrowserContext(browser_context_);
#endif
  plugin_host_clients_.insert(client);
  plugin_service_->OpenChannelToNpapiPlugin(
      render_process_id_, render_frame_id,
      url, policy_url, mime_type, client);
  LOG(INFO) << "[NPAPI] Receive OnOpenChannelToPlugin Msg, id:" << base::GetCurrentProcId();
}

void RenderFrameMessageFilter::OnCompletedOpenChannelToNpapiPlugin(
    RenderFrameMessageFilter::OpenChannelToNpapiPluginCallback* client) {
  DCHECK_CURRENTLY_ON(BrowserThread::IO);
  plugin_host_clients_.erase(client);
}
#endif

void RenderFrameMessageFilter::OnOpenChannelToPepperPlugin(
    const url::Origin& embedder_origin,
    const base::FilePath& path,
    const base::Optional<url::Origin>& origin_lock,
    IPC::Message* reply_msg) {
  // Enforce that the sender of the IPC (i.e. |render_process_id_|) is actually
  // able/allowed to host a frame with |embedder_origin|.
  auto* policy = ChildProcessSecurityPolicyImpl::GetInstance();
  if (!policy->CanAccessDataForOrigin(render_process_id_, embedder_origin)) {
    NOTREACHED() << embedder_origin;
    bad_message::ReceivedBadMessage(
        this, bad_message::RFMF_INVALID_PLUGIN_EMBEDDER_ORIGIN);
    return;
  }

  plugin_service_->OpenChannelToPpapiPlugin(
      render_process_id_, embedder_origin, path, profile_data_directory_,
      origin_lock, new OpenChannelToPpapiPluginCallback(this, reply_msg));
}

void RenderFrameMessageFilter::OnDidCreateOutOfProcessPepperInstance(
    int plugin_child_id,
    int32_t pp_instance,
    PepperRendererInstanceData instance_data,
    bool is_external) {
  // It's important that we supply the render process ID ourselves based on the
  // channel the message arrived on. We use the
  //   PP_Instance -> (process id, frame id)
  // mapping to decide how to handle messages received from the (untrusted)
  // plugin, so an exploited renderer must not be able to insert fake mappings
  // that may allow it access to other render processes.
  DCHECK_EQ(0, instance_data.render_process_id);
  instance_data.render_process_id = render_process_id_;
  if (is_external) {
    // We provide the BrowserPpapiHost to the embedder, so it's safe to cast.
    BrowserPpapiHostImpl* host = static_cast<BrowserPpapiHostImpl*>(
        GetContentClient()->browser()->GetExternalBrowserPpapiHost(
            plugin_child_id));
    if (host)
      host->AddInstance(pp_instance, instance_data);
  } else {
    PpapiPluginProcessHost::DidCreateOutOfProcessInstance(
        plugin_child_id, pp_instance, instance_data);
  }
}

void RenderFrameMessageFilter::OnDidDeleteOutOfProcessPepperInstance(
    int plugin_child_id,
    int32_t pp_instance,
    bool is_external) {
  if (is_external) {
    // We provide the BrowserPpapiHost to the embedder, so it's safe to cast.
    BrowserPpapiHostImpl* host = static_cast<BrowserPpapiHostImpl*>(
        GetContentClient()->browser()->GetExternalBrowserPpapiHost(
            plugin_child_id));
    if (host)
      host->DeleteInstance(pp_instance);
  } else {
    PpapiPluginProcessHost::DidDeleteOutOfProcessInstance(plugin_child_id,
                                                          pp_instance);
  }
}

void RenderFrameMessageFilter::OnOpenChannelToPpapiBroker(
    int routing_id,
    const base::FilePath& path) {
  plugin_service_->OpenChannelToPpapiBroker(
      render_process_id_, routing_id, path,
      new OpenChannelToPpapiBrokerCallback(this, routing_id));
}

void RenderFrameMessageFilter::OnPluginInstanceThrottleStateChange(
    int plugin_child_id,
    int32_t pp_instance,
    bool is_throttled) {
  // Feature is only implemented for non-external Plugins.
  PpapiPluginProcessHost::OnPluginInstanceThrottleStateChange(
      plugin_child_id, pp_instance, is_throttled);
}

#endif  // ENABLE_PLUGINS

}  // namespace content
