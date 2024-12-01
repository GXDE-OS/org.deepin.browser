// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/npapi/webplugin_delegate_proxy.h"

#include <algorithm>
#include <iostream>

#include "base/debug/stack_trace.h"
#include "base/auto_reset.h"
// #include "base/basictypes.h"
#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/process/process.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/version.h"
// #include "cc/resources/shared_bitmap.h"
#include "content/child/child_process.h"
// #include "content/child/child_shared_bitmap_manager.h"
#include "content/child/npapi/npobject_proxy.h"
#include "content/child/npapi/npobject_stub.h"
#include "content/child/npapi/npobject_util.h"
#include "content/child/npapi/webplugin_resource_client.h"
#include "content/child/plugin_messages.h"
#include "content/common/content_constants_internal.h"
#include "content/common/content_switches_internal.h"
//#include "content/public/common/cursor_info.h"
#include "content/common/frame_messages.h"
#include "content/common/view_messages.h"
#include "content/public/renderer/content_renderer_client.h"
#include "content/renderer/npapi/plugin_channel_host.h"
#include "content/renderer/npapi/webplugin_impl.h"
#include "content/renderer/render_frame_impl.h"
#include "content/renderer/render_thread_impl.h"
#include "content/renderer/render_view_impl.h"
#include "content/renderer/sad_plugin.h"
#include "ipc/ipc_channel_handle.h"
#include "net/base/mime_util.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/blink/public/platform/web_drag_data.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/WebBindings.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/skia/src/core/SkDevice.h"
#include "ui/gfx/blit.h"
#include "ui/gfx/canvas.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/gfx/skia_util.h"

#ifdef USE_UNIONTECH_NPAPI
#include "base/rand_util.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "content/child/npapi/plugin_host.h"
#include "content/child/npapi/plugin_instance.h"
#include "content/child/npapi/plugin_lib.h"
#include "content/child/npapi/plugin_url_fetcher.h"
#include "content/child/npapi/webplugin.h"
#include "net/http/http_response_headers.h"
#include "content/child/child_thread_impl.h"
#include "content/child/npapi/webplugin_resource_client.h"
#include "content/child/request_info.h"
#include "content/renderer/loader/request_extra_data.h"
#include "content/renderer/loader/resource_dispatcher.h"
#include "content/renderer/loader/web_url_loader_impl.h"
#include "content/renderer/render_thread_impl.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "third_party/blink/public/platform/web_url_loader_client.h"
#include "third_party/blink/public/platform/web_url_response.h"
#endif

#if defined(OS_WIN)
#include "base/win/scoped_handle.h"
#include "content/public/common/sandbox_init.h"
#endif

using blink::WebBindings;
//using blink::WebCursorInfo;
using blink::WebDragData;
using blink::WebInputEvent;
using blink::WebString;
using blink::WebView;

namespace content {

namespace {

class ScopedLogLevel {
 public:
  explicit ScopedLogLevel(int level);
  ~ScopedLogLevel();

 private:
  int old_level_;

  DISALLOW_COPY_AND_ASSIGN(ScopedLogLevel);
};

ScopedLogLevel::ScopedLogLevel(int level)
    : old_level_(logging::GetMinLogLevel()) {
  logging::SetMinLogLevel(level);
}

ScopedLogLevel::~ScopedLogLevel() {
  logging::SetMinLogLevel(old_level_);
}

// Proxy for WebPluginResourceClient.  The object owns itself after creation,
// deleting itself after its callback has been called.
class ResourceClientProxy : public WebPluginResourceClient {
 public:
  ResourceClientProxy(PluginChannelHost* channel, int instance_id)
      : channel_(channel),
        instance_id_(instance_id),
        resource_id_(0),
        multibyte_response_expected_(false) {}

  ~ResourceClientProxy() override {}

  void Initialize(unsigned long resource_id, const GURL& url, int notify_id) {
    resource_id_ = resource_id;
    channel_->Send(new PluginMsg_HandleURLRequestReply(
        instance_id_, resource_id, url, notify_id));
  }

  void InitializeForSeekableStream(unsigned long resource_id,
                                   int range_request_id) {
    resource_id_ = resource_id;
    multibyte_response_expected_ = true;
    channel_->Send(new PluginMsg_HTTPRangeRequestReply(
        instance_id_, resource_id, range_request_id));
  }

  // PluginResourceClient implementation:
  void WillSendRequest(const GURL& url, int http_status_code) override {
    DCHECK(channel_.get() != NULL);
    channel_->Send(new PluginMsg_WillSendRequest(instance_id_, resource_id_,
                                                 url, http_status_code));
  }

  void DidReceiveResponse(const std::string& mime_type,
                          const std::string& headers,
                          uint32_t expected_length,
                          uint32_t last_modified,
                          bool request_is_seekable) override {
    DCHECK(channel_.get() != NULL);
    PluginMsg_DidReceiveResponseParams params;
    params.id = resource_id_;
    params.mime_type = mime_type;
    params.headers = headers;
    params.expected_length = expected_length;
    params.last_modified = last_modified;
    params.request_is_seekable = request_is_seekable;
    // Grab a reference on the underlying channel so it does not get
    // deleted from under us.
    scoped_refptr<PluginChannelHost> channel_ref(channel_);
    channel_->Send(new PluginMsg_DidReceiveResponse(instance_id_, params));
  }

  void DidReceiveData(const char* buffer,
                      int length,
                      int data_offset) override {
    DCHECK(channel_.get() != NULL);
    DCHECK_GT(length, 0);
    std::vector<char> data;
    data.resize(static_cast<size_t>(length));
    memcpy(&data.front(), buffer, length);
    // Grab a reference on the underlying channel so it does not get
    // deleted from under us.
    scoped_refptr<PluginChannelHost> channel_ref(channel_);
    channel_->Send(new PluginMsg_DidReceiveData(instance_id_, resource_id_,
                                                data, data_offset));
  }

  void DidFinishLoading(unsigned long resource_id) override {
    DCHECK(channel_.get() != NULL);
    DCHECK_EQ(resource_id, resource_id_);
    channel_->Send(new PluginMsg_DidFinishLoading(instance_id_, resource_id_));
    channel_ = nullptr;
    base::ThreadTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, this);
  }

  void DidFail(unsigned long resource_id) override {
    DCHECK(channel_.get() != NULL);
    DCHECK_EQ(resource_id, resource_id_);
    channel_->Send(new PluginMsg_DidFail(instance_id_, resource_id_));
    channel_ = nullptr;
    base::ThreadTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, this);
  }

  bool IsMultiByteResponseExpected() override {
    return multibyte_response_expected_;
  }

  int ResourceId() override { return resource_id_; }

 private:
  scoped_refptr<PluginChannelHost> channel_;
  int instance_id_;
  unsigned long resource_id_;
  // Set to true if the response expected is a multibyte response.
  // For e.g. response for a HTTP byte range request.
  bool multibyte_response_expected_;
};

int GetInitialRequestID() {
  // Starting with a random number speculatively avoids RDH_INVALID_REQUEST_ID
  // which are assumed to have been caused by restarting RequestID at 0 when
  // restarting a renderer after a crash - this would cause collisions if
  // requests from the previously crashed renderer are still active.  See
  // https://crbug.com/614281#c61 for more details about this hypothesis.
  //
  // To avoid increasing the likelyhood of overflowing the range of available
  // RequestIDs, kMax is set to a relatively low value of 2^20 (rather than
  // to something higher like 2^31).
  const int kMin = 1 << 10;
  const int kMax = 1 << 20;
  return base::RandInt(kMin, kMax);
}

int MakeRequestID() {
  // NOTE: The resource_dispatcher_host also needs probably unique
  // request_ids, so they count down from -2 (-1 is a special "we're
  // screwed value"), while the renderer process counts up.
  static const int kInitialRequestID = GetInitialRequestID();
  static base::AtomicSequenceNumber sequence;
  return kInitialRequestID + sequence.GetNext();
}

}  // namespace

WebPluginDelegateProxy::WebPluginDelegateProxy(
    WebPluginImpl* plugin,
    const std::string& mime_type,
    const base::WeakPtr<RenderViewImpl>& render_view,
    RenderFrameImpl* render_frame)
    : render_view_(render_view),
      render_frame_(render_frame),
      plugin_(plugin),
      uses_shared_bitmaps_(false),
      window_(gfx::kNullPluginWindow),
      mime_type_(mime_type),
      instance_id_(MSG_ROUTING_NONE),
      npobject_(NULL),
      npp_(new NPP_t),
      sad_plugin_(NULL),
      invalidate_pending_(false),
      transparent_(false),
      front_buffer_index_(0) {
  if (render_view_->GetWebView()->MainFrame()->IsWebLocalFrame()) {
    page_url_ = render_view_->GetWebView()->MainFrame()->ToWebLocalFrame()->GetDocument().Url();
  } else {
    page_url_ = render_view_->GetWebView()->FocusedFrame()->GetDocument().Url();
  }
}

WebPluginDelegateProxy::~WebPluginDelegateProxy() {
  if (npobject_)
    WebBindings::releaseObject(npobject_);
}

WebPluginDelegateProxy::SharedBitmap::SharedBitmap() {}

WebPluginDelegateProxy::SharedBitmap::~SharedBitmap() {}

void WebPluginDelegateProxy::PluginDestroyed() {

  if (window_)
    WillDestroyWindow();

  std::cout << "---- [TODO] WebPluginDelegateProxy::PluginDestroyed ----" << std::endl;
  if (render_frame_)
    render_frame_->UnregisterPluginDelegate(this);
  if (channel_host_.get()) {
    Send(new PluginMsg_DestroyInstance(instance_id_));

    // Must remove the route after sending the destroy message, rather than
    // before, since RemoveRoute can lead to all the outstanding NPObjects
    // being told the channel went away if this was the last instance.
    channel_host_->RemoveRoute(instance_id_);

    // Remove the mapping between our instance-Id and NPP identifiers, used by
    // the channel to track object ownership, before releasing it.
    channel_host_->RemoveMappingForNPObjectOwner(instance_id_);

    // Release the channel host now. If we are is the last reference to the
    // channel, this avoids a race where this renderer asks a new connection to
    // the same plugin between now and the time 'this' is actually deleted.
    // Destroying the channel host is what releases the channel name -> FD
    // association on POSIX, and if we ask for a new connection before it is
    // released, the plugin will give us a new FD, and we'll assert when trying
    // to associate it with the channel name.
    channel_host_ = nullptr;
  }

  plugin_ = nullptr;

  base::ThreadTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, this);
}

bool WebPluginDelegateProxy::Initialize(
    const GURL& url,
    const std::vector<std::string>& arg_names,
    const std::vector<std::string>& arg_values,
    bool load_manually) {
  // TODO(shess): Attempt to work around http://crbug.com/97285 and
  // http://crbug.com/141055 by retrying the connection.  Reports seem
  // to indicate that the plugin hasn't crashed, and that the problem
  // is not 100% persistent.
  const size_t kAttempts = 2;

  bool result = false;
  scoped_refptr<PluginChannelHost> channel_host;
  int instance_id = 0;    
  for (size_t attempt = 0; !result && attempt < kAttempts; attempt++) {

    IPC::ChannelHandle channel_handle;
    if (!RenderThreadImpl::current()->Send(new FrameHostMsg_OpenChannelToPlugin(
            render_frame_->GetRoutingID(), url, page_url_, mime_type_,
            &channel_handle, &info_))) {
      continue;
    }

    if (channel_handle.name.empty()) {
      // We got an invalid handle.  Either the plugin couldn't be found (which
      // shouldn't happen, since if we got here the plugin should exist) or the
      // plugin crashed on initialization.
      if (!info_.path.empty()) {
        render_view_->GetMainRenderFrame()->PluginCrashed(info_.path, base::kNullProcessId);
        LOG(ERROR) << "Plugin crashed on start";

        // Return true so that the plugin widget is created and we can paint the
        // crashed plugin there.
        return true;
      }
      LOG(ERROR) << "Plugin couldn't be found";
      return false;
    }

    LOG(INFO) << "[NPAPI] renderer <--> plugin ipc channel is ok";

    channel_host =
        PluginChannelHost::GetPluginChannelHost(
            channel_handle, ChildProcess::current()->io_task_runner());
    if (!channel_host.get()) {
      LOG(ERROR) << "Couldn't get PluginChannelHost";
      continue;
    }

    {
      // TODO(bauerb): Debugging for http://crbug.com/141055.
      ScopedLogLevel log_level(-2);  // Equivalent to --v=2
      result = channel_host->Send(new PluginMsg_CreateInstance(
          mime_type_, &instance_id));                               
      if (!result) {
        LOG(ERROR) << "Couldn't send PluginMsg_CreateInstance";
        continue;
      }
    }
  }
  
  // Failed too often, give up.
  if (!result){
    LOG(ERROR) << "[NPAPI]WebPluginDelegateProxy::Initialize FAILED";
    return false;
  }

  channel_host_ = channel_host;
  instance_id_ = instance_id;

  channel_host_->AddRoute(instance_id_, this, NULL);

  // Inform the channel of the mapping between our instance-Id and dummy NPP
  // identifier, for use in object ownership tracking.
  channel_host_->AddMappingForNPObjectOwner(instance_id_, GetPluginNPP());

  // Now tell the PluginInstance in the plugin process to initialize.
  PluginMsg_Init_Params params;
  params.url = url;
  params.page_url = page_url_;
  params.arg_names = arg_names;
  params.arg_values = arg_values;
  if (render_view_->GetMainRenderFrame()) {
    if (render_view_->GetMainRenderFrame()->GetWidget()) {
      params.host_render_view_routing_id = render_view_->GetMainRenderFrame()->GetWidget()->routing_id();
    } else {
    }
  } else {
    params.host_render_view_routing_id = render_frame_->GetLocalRootRenderWidget()->routing_id();
  }

  params.load_manually = load_manually;

  LOG(INFO) << "[NPAPI] PluginMsg_Init url:" << url.spec();
  LOG(INFO) << "[NPAPI] PluginMsg_Init page_url:" << page_url_.spec();
  LOG(INFO) << "[NPAPI] PluginMsg_Init instance_id:" << instance_id_;

  result = false;
  Send(new PluginMsg_Init(instance_id_, params, &transparent_, &result));

  if (!result) {
    LOG(WARNING) << "[NPAPI] PluginMsg_Init return false";
  }

  render_frame_->RegisterPluginDelegate(this);
  return result;
}

bool WebPluginDelegateProxy::Send(IPC::Message* msg) {
  if (!channel_host_.get()) {
    DLOG(WARNING) << "dropping message because channel host is null";
    delete msg;
    return false;
  }  
  return channel_host_->Send(msg);
}

void WebPluginDelegateProxy::SendJavaScriptStream(const GURL& url,
                                                  const std::string& result,
                                                  bool success,
                                                  int notify_id) {
  Send(new PluginMsg_SendJavaScriptStream(instance_id_, url, result, success,
                                          notify_id));
}

void WebPluginDelegateProxy::DidReceiveManualResponse(
    const GURL& url,
    const std::string& mime_type,
    const std::string& headers,
    uint32_t expected_length,
    uint32_t last_modified) {
  PluginMsg_DidReceiveResponseParams params;
  params.id = 0;
  params.mime_type = mime_type;
  params.headers = headers;
  params.expected_length = expected_length;
  params.last_modified = last_modified;
  Send(new PluginMsg_DidReceiveManualResponse(instance_id_, url, params));
}

void WebPluginDelegateProxy::DidReceiveManualData(const char* buffer,
                                                  int length) {
  DCHECK_GT(length, 0);
  std::vector<char> data;
  data.resize(static_cast<size_t>(length));
  memcpy(&data.front(), buffer, length);
  Send(new PluginMsg_DidReceiveManualData(instance_id_, data));
}

void WebPluginDelegateProxy::DidFinishManualLoading() {
  Send(new PluginMsg_DidFinishManualLoading(instance_id_));
}

void WebPluginDelegateProxy::DidManualLoadFail() {
  Send(new PluginMsg_DidManualLoadFail(instance_id_));
}

bool WebPluginDelegateProxy::OnMessageReceived(const IPC::Message& msg) {
  GetContentClient()->SetActiveURL(page_url_, page_url_.spec());

  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(WebPluginDelegateProxy, msg)
    IPC_MESSAGE_HANDLER(PluginHostMsg_SetWindow, OnSetWindow)
    IPC_MESSAGE_HANDLER(PluginHostMsg_CancelResource, OnCancelResource)
    IPC_MESSAGE_HANDLER(PluginHostMsg_InvalidateRect, OnInvalidateRect)
    IPC_MESSAGE_HANDLER(PluginHostMsg_GetWindowScriptNPObject,
                        OnGetWindowScriptNPObject)
    IPC_MESSAGE_HANDLER(PluginHostMsg_GetPluginElement, OnGetPluginElement)
    IPC_MESSAGE_HANDLER(PluginHostMsg_ResolveProxy, OnResolveProxy)
    IPC_MESSAGE_HANDLER(PluginHostMsg_SetCookie, OnSetCookie)
    IPC_MESSAGE_HANDLER(PluginHostMsg_GetCookies, OnGetCookies)
    IPC_MESSAGE_HANDLER(PluginHostMsg_URLRequest, OnHandleURLRequest)
    IPC_MESSAGE_HANDLER(PluginHostMsg_CancelDocumentLoad, OnCancelDocumentLoad)
    IPC_MESSAGE_HANDLER(PluginHostMsg_InitiateHTTPRangeRequest,
                        OnInitiateHTTPRangeRequest)
    IPC_MESSAGE_HANDLER(PluginHostMsg_DidStartLoading, OnDidStartLoading)
    IPC_MESSAGE_HANDLER(PluginHostMsg_DidStopLoading, OnDidStopLoading)
    IPC_MESSAGE_HANDLER(PluginHostMsg_DeferResourceLoading,
                        OnDeferResourceLoading)
    IPC_MESSAGE_HANDLER(PluginHostMsg_URLRedirectResponse,
                        OnURLRedirectResponse)
    IPC_MESSAGE_HANDLER(PluginHostMsg_CheckIfRunInsecureContent,
                        OnCheckIfRunInsecureContent)
                        
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()
  DCHECK(handled);
  return handled;
}

void WebPluginDelegateProxy::OnChannelError() {
  if (plugin_) {
    if (window_) {
      // The actual WebPluginDelegate never got a chance to tell the WebPlugin
      // its window was going away. Do it on its behalf.
      WillDestroyWindow();
    }
    plugin_->Invalidate();
  }
  if (channel_host_.get() && !channel_host_->expecting_shutdown()) {
    render_view_->GetMainRenderFrame()->PluginCrashed(
        info_.path, channel_host_->peer_pid());
  }
}

static void CopyTransportDIBHandleForMessage(
    const TransportDIB::Handle& handle_in,
    TransportDIB::Handle* handle_out,
    base::ProcessId peer_pid) {
#if defined(OS_POSIX)
  *handle_out = handle_in;
#else
#error Shared memory copy not implemented.
#endif
}

void WebPluginDelegateProxy::SendUpdateGeometry(
    bool bitmaps_changed) {
  if (!channel_host_.get())
    return;

  PluginMsg_UpdateGeometry_Param param;
  param.window_rect = plugin_rect_;
  param.clip_rect = clip_rect_;
  param.windowless_buffer0 = TransportDIB::DefaultHandleValue();
  param.windowless_buffer1 = TransportDIB::DefaultHandleValue();
  param.windowless_buffer_index = back_buffer_index();
  param.peer_pid = base::GetCurrentProcId();

#if defined(OS_POSIX)
   // If we're using POSIX mmap'd TransportDIBs, sending the handle across
   // IPC establishes a new mapping rather than just sending a window ID,
   // so only do so if we've actually changed the shared memory bitmaps.
  if (bitmaps_changed)
#endif
  {
    if (transport_stores_[0].bitmap) {
      param.windowless_buffer0 = transport_stores_[0].transport_dib->handle();
      param.buffer0_size = transport_stores_[0].transport_dib->size();

    }

    if (transport_stores_[1].bitmap) {
        param.windowless_buffer1 = transport_stores_[1].transport_dib->handle();
        param.buffer1_size = transport_stores_[1].transport_dib->size();

    }
  }

  IPC::Message* msg;
  {
    DLOG(INFO) << "[NPAPI]WebPluginDelegateProxy send PluginMsg_UpdateGeometry";
    msg = new PluginMsg_UpdateGeometry(instance_id_, param);
    msg->set_unblock(true);
  }

  Send(msg);
}

void WebPluginDelegateProxy::UpdateGeometry(const gfx::Rect& window_rect,
                                            const gfx::Rect& clip_rect) {
  // window_rect becomes either a window in native windowing system
  // coords, or a backing buffer.  In either case things will go bad
  // if the rectangle is very large.
  if (window_rect.width() < 0  || window_rect.width() > kMaxPluginSideLength ||
      window_rect.height() < 0 || window_rect.height() > kMaxPluginSideLength ||
      // We know this won't overflow due to above checks.
      static_cast<uint32_t>(window_rect.width()) *
          static_cast<uint32_t>(window_rect.height()) > kMaxPluginSize) { 
    return;
  }

  plugin_rect_ = window_rect;
  clip_rect_ = clip_rect;

  bool bitmaps_changed = false;

  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::UpdateGeometry";

  if (uses_shared_bitmaps_ && (!front_buffer_bitmap() ||
      (window_rect.width() != front_buffer_bitmap()->width() ||
       window_rect.height() !=
           front_buffer_bitmap()->height()))) {
    bitmaps_changed = true;

    // Create a shared memory section that the plugin paints into
    // asynchronously.
    ResetWindowlessBitmaps();
    if (!window_rect.IsEmpty()) {
      if (!CreateSharedBitmap(&transport_stores_[0].transport_dib,
                              &transport_stores_[0].bitmap,
                              &transport_stores_[0].canvas) ||
          !CreateSharedBitmap(&transport_stores_[1].transport_dib,
                              &transport_stores_[1].bitmap,
                              &transport_stores_[1].canvas)) {
        DCHECK(false);
        ResetWindowlessBitmaps();
        return;
      }
    }
  }
  
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::UpdateGeometry->SendUpdateGeometry";
  SendUpdateGeometry(bitmaps_changed);
}

void WebPluginDelegateProxy::ResetWindowlessBitmaps() {
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::ResetWindowlessBitmaps";
  transport_stores_[0].transport_dib.reset();
  transport_stores_[1].transport_dib.reset();

  transport_stores_[0].canvas.reset();
  transport_stores_[1].canvas.reset();

  transport_stores_[0].bitmap.reset();
  transport_stores_[1].bitmap.reset();
  transport_store_painted_ = gfx::Rect();
  front_buffer_diff_ = gfx::Rect();
}

static size_t BitmapSizeForPluginRect(const gfx::Rect& plugin_rect) {
  const size_t stride =
      skia::PlatformCanvasStrideForWidth(plugin_rect.width());
  return stride * plugin_rect.height();
}

#if !defined(OS_WIN)
#if 0
bool WebPluginDelegateProxy::CreateLocalBitmap(
    std::vector<uint8_t>* memory,
    std::unique_ptr<skia::PlatformCanvas>* canvas) {
  const size_t size = BitmapSizeForPluginRect(plugin_rect_);
  memory->resize(size);
  if (memory->size() != size)
    return false;
  canvas->reset(skia::CreatePlatformCanvas(
      plugin_rect_.width(), plugin_rect_.height(), true, &((*memory)[0]),
      skia::CRASH_ON_FAILURE));
  return true;
}
#endif
#endif

bool WebPluginDelegateProxy::CreateSharedBitmap(
    std::unique_ptr<TransportDIB>* memory,
    std::unique_ptr<SkBitmap>* bitmap,
    std::unique_ptr<SkCanvas>* canvas) {
  const size_t size = BitmapSizeForPluginRect(plugin_rect_);
#if defined(OS_POSIX)
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::CreateSharedBitmap start";
  memory->reset(TransportDIB::Create(size, 0));
  if (!memory->get()) {
    LOG(ERROR) << "[NPAPI] WebPluginDelegateProxy::CreateSharedBitmap FAILED!!";
    return false;
  }
#endif
#if defined(OS_POSIX) && !BUILDFLAG(USE_GTK) && !defined(OS_ANDROID)
  TransportDIB::Handle handle;
  IPC::Message* msg = new ViewHostMsg_AllocTransportDIB(size, false, &handle);
  if (!RenderThreadImpl::current()->Send(msg))
    return false;
  if (handle.fd < 0)
    return false;
  memory->reset(TransportDIB::Map(handle));
#else
  static uint32_t sequence_number = 0;
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::CreateSharedBitmap create memory";
  memory->reset(TransportDIB::Create(size, sequence_number++));
#endif
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::CreateSharedBitmap create canvas";
  *bitmap = (*memory)->GetPlatformCanvasGTK(plugin_rect_.width(),
                                         plugin_rect_.height(), true);
   *canvas = std::make_unique<SkCanvas>(*(bitmap->get()));
  return !!canvas->get();
}

void WebPluginDelegateProxy::Paint(cc::PaintCanvas* canvas,
                                   const gfx::Rect& damaged_rect) {
  // Limit the damaged rectangle to whatever is contained inside the plugin
  // rectangle, as that's the rectangle that we'll actually draw.
  DLOG(INFO) << "[TODO] WebPluginDelegateProxy::Paint";
  gfx::Rect rect = gfx::IntersectRects(damaged_rect, plugin_rect_);

  // If the plugin is no longer connected (channel crashed) draw a crashed
  // plugin bitmap
  if (!channel_host_.get() || !channel_host_->channel_valid()) {
    // Lazily load the sad plugin image.
    if (!sad_plugin_)
      sad_plugin_ = GetContentClient()->renderer()->GetSadPluginBitmap();
    if (sad_plugin_)
      PaintSadPlugin(canvas, plugin_rect_, cc::PaintImage::CreateFromBitmap(*sad_plugin_));

    LOG(INFO) << "[TODO] WebPluginDelegateProxy::Paint sad_plugin";
    return;
  }

  if (window_ != 0) {
    cc::PaintFlags flags;
    flags.setBlendMode(SkBlendMode::kSrc);
    flags.setColor(SK_ColorWHITE);
    flags.setStyle(cc::PaintFlags::kFill_Style);

    canvas->drawRect(SkRect{rect.x(), rect.y(), rect.right(), rect.bottom() }, flags);
  }

  if (!uses_shared_bitmaps_) {
    LOG(INFO) << "[TODO] WebPluginDelegateProxy::Paint return 1";
    return;
  }

  // We got a paint before the plugin's coordinates, so there's no buffer to
  // copy from.
  if (!front_buffer_canvas()) {
    LOG(INFO) << "[TODO] WebPluginDelegateProxy::Paint return 2";
    return;
  }

  gfx::Rect offset_rect = rect;
  offset_rect.Offset(-plugin_rect_.x(), -plugin_rect_.y());

  // transport_store_painted_ is really a bounding box, so in principle this
  // check could falsely indicate that we don't need to paint offset_rect, but
  // in practice it works fine.
  if (!transport_store_painted_.Contains(offset_rect)) {
    LOG(INFO) << "[TODO] WebPluginDelegateProxy::Paint send PluginMsg_Paint";
    Send(new PluginMsg_Paint(instance_id_, offset_rect));
    // Since the plugin is not blocked on the renderer in this context, there is
    // a chance that it will begin repainting the back-buffer before we complete
    // capturing the data. Buffer flipping would increase that risk because
    // geometry update is asynchronous, so we don't want to use buffer flipping
    // here.
    UpdateFrontBuffer(offset_rect, false);
  }
  DLOG(INFO) << "[NPAPI] WebPluginDelegateProxy::Paint drawBitmapRect";
  cc::PaintFlags flags;
  // flags.setAlpha(200);
  flags.setBlendMode(SkBlendMode::kSrcOver);
  canvas->drawImage(cc::PaintImage::CreateFromBitmap(*front_buffer_bitmap()),
      plugin_rect_.x(), plugin_rect_.y(), &flags);
   
  if (invalidate_pending_) {
    // Only send the PaintAck message if this paint is in response to an
    // invalidate from the plugin, since this message acts as an access token
    // to ensure only one process is using the shared bitmap at a time.
    invalidate_pending_ = false;
    DLOG(INFO) << "[TODO] WebPluginDelegateProxy::Paint PluginMsg_DidPaint  invalidate_pending_ "<< invalidate_pending_;
    Send(new PluginMsg_DidPaint(instance_id_));
  }
}

NPObject* WebPluginDelegateProxy::GetPluginScriptableObject() {
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::GetPluginScriptableObject";
  if (npobject_)
    return WebBindings::retainObject(npobject_);

  if (!channel_host_.get())
    return NULL;

  int route_id = MSG_ROUTING_NONE;
  Send(new PluginMsg_GetPluginScriptableObject(instance_id_, &route_id));
  if (route_id == MSG_ROUTING_NONE)
    return NULL;

  if (!channel_host_.get())
    return nullptr;

  npobject_ = NPObjectProxy::Create(channel_host_.get(), route_id, 0, page_url_,
                                    GetPluginNPP());

  return WebBindings::retainObject(npobject_);
}

NPP WebPluginDelegateProxy::GetPluginNPP() {
  // Return a dummy NPP for WebKit to use to identify this plugin.
  return npp_.get();
}

bool WebPluginDelegateProxy::GetFormValue(base::string16* value) {
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::GetFormValue";
  bool success = false;
  Send(new PluginMsg_GetFormValue(instance_id_, value, &success));
  return success;
}

void WebPluginDelegateProxy::DidFinishLoadWithReason(
    const GURL& url, NPReason reason, int notify_id) {
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::DidFinishLoadWithReason";
  Send(new PluginMsg_DidFinishLoadWithReason(
      instance_id_, url, reason, notify_id));
}

void WebPluginDelegateProxy::SetFocus(bool focused) {
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::SetFocus";
  Send(new PluginMsg_SetFocus(instance_id_, focused));
}

bool WebPluginDelegateProxy::HandleInputEvent(
    const WebInputEvent& event,
    ui::Cursor* cursor_info) {
  bool handled = false;
  WebCursor cursor;
  // A windowless plugin can enter a modal loop in the context of a
  // NPP_HandleEvent call, in which case we need to pump messages to
  // the plugin. We pass of the corresponding event handle to the
  // plugin process, which is set if the plugin does enter a modal loop.
  IPC::SyncMessage* message =
      new PluginMsg_HandleInputEvent(instance_id_, &event, &handled, &cursor);
  message->set_pump_messages_event(modal_loop_pump_messages_event_.get());
  Send(message);
  return handled;
}

int WebPluginDelegateProxy::GetProcessId() {
  return channel_host_->peer_pid();
}

void WebPluginDelegateProxy::SetContentAreaFocus(bool has_focus) {
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::SetContentAreaFocus";
  IPC::Message* msg = new PluginMsg_SetContentAreaFocus(instance_id_,
                                                        has_focus);
  // Make sure focus events are delivered in the right order relative to
  // sync messages they might interact with (Paint, HandleEvent, etc.).
  msg->set_unblock(true);
  Send(msg);
}

void WebPluginDelegateProxy::OnSetWindow(gfx::PluginWindowHandle window) {
  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy::OnSetWindow window:" << window;
  uses_shared_bitmaps_ = !window;
  window_ = window;
  if (plugin_)
    plugin_->SetWindow(window);
}

void WebPluginDelegateProxy::WillDestroyWindow() {
  DCHECK(window_);
  plugin_->WillDestroyWindow(window_);
  window_ = gfx::kNullPluginWindow;
}

void WebPluginDelegateProxy::OnCancelResource(int id) {
  if (plugin_)
    plugin_->CancelResource(id);
}

void WebPluginDelegateProxy::OnInvalidateRect(const gfx::Rect& rect) {
  if (!plugin_)
    return;

  // Clip the invalidation rect to the plugin bounds; the plugin may have been
  // resized since the invalidate message was sent.
  gfx::Rect clipped_rect =
      gfx::IntersectRects(rect, gfx::Rect(plugin_rect_.size()));

  invalidate_pending_ = true;
  // The plugin is blocked on the renderer because the invalidate message it has
  // sent us is synchronous, so we can use buffer flipping here if the caller
  // allows it.
  UpdateFrontBuffer(clipped_rect, true);
  plugin_->InvalidateRect(clipped_rect);
}

void WebPluginDelegateProxy::OnGetWindowScriptNPObject(
    int route_id, bool* success) {
  *success = false;
  NPObject* npobject = NULL;

  LOG(INFO) << "[NPAPI] WebPluginDelegateProxy GOT msg PluginHostMsg_GetWindowScriptNPObject";

  if (plugin_) {
    LOG(INFO) << "[NPAPI] WebPluginDelegateProxy CALL Webplugin_Impl GetWindowScriptNPObject";
    npobject = plugin_->GetWindowScriptNPObject();
  }

  if (!npobject) {
    LOG(ERROR) << "WebPluginDelegateProxy::OnGetWindowScriptNPObject FAILED!!";
    return;
  }

  // The stub will delete itself when the proxy tells it that it's released, or
  // otherwise when the channel is closed.
  new NPObjectStub(npobject, channel_host_.get(), route_id, 0, page_url_);
  *success = true;
}

void WebPluginDelegateProxy::OnResolveProxy(const GURL& url,
                                            bool* result,
                                            std::string* proxy_list) {
  *result = RenderThreadImpl::current()->ResolveProxy(url, proxy_list);
}

void WebPluginDelegateProxy::OnGetPluginElement(int route_id, bool* success) {
  LOG(INFO) << "[NPAPI]WebPluginDelegateProxy::OnGetPluginElement";
  *success = false;
  NPObject* npobject = NULL;

  if (plugin_) {
    npobject = plugin_->GetPluginElement();
  }
  if (!npobject) {
    LOG(ERROR) << "[NPAPI]WebPluginDelegateProxy::OnGetPluginElement npobject is null!";
    return;
  }

  // The stub will delete itself when the proxy tells it that it's released, or
  // otherwise when the channel is closed.
  new NPObjectStub(npobject, channel_host_.get(), route_id, 0, page_url_);
  *success = true;
}

void WebPluginDelegateProxy::OnSetCookie(const GURL& url,
                                         const GURL& first_party_for_cookies,
                                         const std::string& cookie) {
  if (plugin_)
    plugin_->SetCookie(url, first_party_for_cookies, cookie);
}

void WebPluginDelegateProxy::OnGetCookies(const GURL& url,
                                          const GURL& first_party_for_cookies,
                                          std::string* cookies) {
  DCHECK(cookies);
  if (plugin_)
    *cookies = plugin_->GetCookies(url, first_party_for_cookies);
}

void WebPluginDelegateProxy::CopyFromBackBufferToFrontBuffer(
    const gfx::Rect& rect) {
  DLOG(INFO) << "[NPAPI] WebPluginDelegateProxy::CopyFromBackBufferToFrontBuffer";
  //BlitCanvasToCanvas(front_buffer_canvas(),
  //                   rect,
  //                   back_buffer_canvas(),
  //                   rect.origin());
  front_buffer_canvas()->drawBitmap(*back_buffer_bitmap(), 0, 0, NULL);

}

void WebPluginDelegateProxy::UpdateFrontBuffer(
    const gfx::Rect& rect,
    bool allow_buffer_flipping) {
  if (!front_buffer_canvas()) {
    return;
  }

  // Plugin has just painted "rect" into the back-buffer, so the front-buffer
  // no longer holds the latest content for that rectangle.
  front_buffer_diff_.Subtract(rect);
  if (allow_buffer_flipping && front_buffer_diff_.IsEmpty()) {
    // Back-buffer contains the latest content for all areas; simply flip
    // the buffers.
    front_buffer_index_ = back_buffer_index();
    SendUpdateGeometry(false);
    // The front-buffer now holds newer content for this region than the
    // back-buffer.
    front_buffer_diff_ = rect;
  } else {
    // Back-buffer contains the latest content for "rect" but the front-buffer
    // contains the latest content for some other areas (or buffer flipping not
    // allowed); fall back to copying the data.
    CopyFromBackBufferToFrontBuffer(rect);
  }
  transport_store_painted_.Union(rect);
}

void WebPluginDelegateProxy::OnHandleURLRequest(
    const PluginHostMsg_URLRequest_Params& params) {
  const char* data = NULL;
  if (params.buffer.size())
    data = &params.buffer[0];

  const char* target = NULL;
  if (params.target.length())
    target = params.target.c_str();

  plugin_->HandleURLRequest(
      params.url.c_str(), params.method.c_str(), target, data,
      static_cast<unsigned int>(params.buffer.size()), params.notify_id,
      params.popups_allowed, params.notify_redirects);
}

WebPluginResourceClient* WebPluginDelegateProxy::CreateResourceClient(
    unsigned long resource_id, const GURL& url, int notify_id) {
  if (!channel_host_.get())
    return NULL;

  ResourceClientProxy* proxy =
      new ResourceClientProxy(channel_host_.get(), instance_id_);
  proxy->Initialize(resource_id, url, notify_id);
  return proxy;
}

WebPluginResourceClient* WebPluginDelegateProxy::CreateSeekableResourceClient(
    unsigned long resource_id, int range_request_id) {
  if (!channel_host_.get())
    return NULL;

  ResourceClientProxy* proxy =
      new ResourceClientProxy(channel_host_.get(), instance_id_);
  proxy->InitializeForSeekableStream(resource_id, range_request_id);
  return proxy;
}

#if 0
void WebPluginDelegateProxy::OnFetchResourceComplete(
    const PluginResourceFetcher::Resource& resource) {
  int request_id = resource.request_id;
  std::map<int, std::unique_ptr<PluginResourceFetcher>>::iterator it =
      plugin_src_fetcher_.find(request_id);

  if (it != plugin_src_fetcher_.end()) {

    PluginMsg_FetchedURL_Params params;

    params.request_id = resource.request_id;
    params.resource_id = resource.resource_id;
    params.response_code = resource.response_code;
    params.mime = resource.mime;
    params.head = resource.head;
    params.data = resource.data;

    Send(new PluginMsg_FetchedURL(instance_id_, params));

    plugin_src_fetcher_.erase(it);
  }
}
#endif

void WebPluginDelegateProxy::FetchURL(unsigned long resource_id,
                                      int notify_id,
                                      const GURL& url,
                                      const GURL& first_party_for_cookies,
                                      const std::string& method,
                                      const char* buf,
                                      unsigned int len,
                                      const Referrer& referrer,
                                      bool notify_redirects,
                                      bool is_plugin_src_load,
                                      int origin_pid,
                                      int render_frame_id,
                                      int render_view_id) {
  if ((referrer.policy == network::mojom::ReferrerPolicy::kDefault ||
       referrer.policy == network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade) &&
      referrer.url.SchemeIsCryptographic() && !url.SchemeIsCryptographic()) {
    LOG(FATAL) << "Trying to send secure referrer for insecure request "
               << "without an appropriate referrer policy.\n"
               << "URL = " << url << "\n"
               << "Referrer = " << referrer.url;
  }

  int request_id = MakeRequestID();
  LOG(INFO) << "WebPluginDelegateProxy::FetchURL URL=" << url;
  LOG(INFO) << "WebPluginDelegateProxy::FetchURL first_party_for_cookies=" << first_party_for_cookies;
  LOG(INFO) << "WebPluginDelegateProxy::FetchURL Referrer=" << referrer.url;

  PluginMsg_FetchURL_Params params;
  params.request_id = request_id;
  params.resource_id = resource_id;
  params.notify_id = notify_id;
  params.url = url;
  params.first_party_for_cookies = first_party_for_cookies;
  params.method = method;
  if (len) {
    params.post_data.resize(len);
    memcpy(&params.post_data.front(), buf, len);
  }
  params.referrer = referrer.url;
  params.referrer_policy = referrer.policy;
  params.notify_redirect = notify_redirects;
  params.is_plugin_src_load = is_plugin_src_load;
  params.render_frame_id = render_frame_id;
  Send(new PluginMsg_FetchURL(instance_id_, params));
}

gfx::PluginWindowHandle WebPluginDelegateProxy::GetPluginWindowHandle() {
  return window_;
}

void WebPluginDelegateProxy::OnCancelDocumentLoad() {
  plugin_->CancelDocumentLoad();
}

void WebPluginDelegateProxy::OnInitiateHTTPRangeRequest(
    const std::string& url,
    const std::string& range_info,
    int range_request_id) {
  plugin_->InitiateHTTPRangeRequest(url.c_str(), range_info.c_str(),
                                    range_request_id);
}

void WebPluginDelegateProxy::OnDidStartLoading() {
  plugin_->DidStartLoading();
}

void WebPluginDelegateProxy::OnDidStopLoading() {
  plugin_->DidStopLoading();
}

void WebPluginDelegateProxy::OnDeferResourceLoading(unsigned long resource_id,
                                                    bool defer) {
  plugin_->SetDeferResourceLoading(resource_id, defer);
}

void WebPluginDelegateProxy::OnURLRedirectResponse(bool allow,
                                                   int resource_id) {
  if (!plugin_)
    return;

  plugin_->URLRedirectResponse(allow, resource_id);
}

void WebPluginDelegateProxy::OnCheckIfRunInsecureContent(const GURL& url,
                                                         bool* result) {
  *result = plugin_->CheckIfRunInsecureContent(url);
}

}  // namespace content
