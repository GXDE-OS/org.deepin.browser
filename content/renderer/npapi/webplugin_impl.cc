// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/npapi/webplugin_impl.h"

#include <iostream>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/debug/crash_logging.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/linked_ptr.h"
#include "base/metrics/user_metrics_action.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "content/child/multipart_response_delegate.h"
#include "content/child/npapi/plugin_host.h"
#include "content/child/npapi/plugin_instance.h"
#include "content/child/npapi/webplugin_delegate_impl.h"
#include "content/child/npapi/webplugin_resource_client.h"
#include "content/common/view_messages.h"
#include "content/public/common/content_constants.h"
#include "content/public/common/content_switches.h"
#include "content/public/renderer/content_renderer_client.h"
// #include "content/renderer/appcache/web_application_cache_host_impl.h"
#include "third_party/blink/renderer/core/loader/appcache/application_cache_host.h"
#include "content/renderer/npapi/webplugin_delegate_proxy.h"
#include "content/renderer/render_frame_impl.h"
#include "content/renderer/render_process.h"
#include "content/renderer/render_thread_impl.h"
#include "content/renderer/render_view_impl.h"
#include "net/base/escape.h"
#include "net/base/net_errors.h"
#include "net/http/http_response_headers.h"
#include "skia/ext/platform_canvas.h"
// #include "third_party/blink/public/platform/web_cookie_jar.h"
#include "third_party/blink/renderer/core/loader/cookie_jar.h"
// #include "third_party/blink/public/platform/web_cursor_info.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/platform/web_http_body.h"
#include "third_party/blink/public/platform/web_http_header_visitor.h"
// #include "third_party/blink/public/platform/web_input_event.h"
// #include "third_party/blink/public/platform/web_keyboard_event.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_loader.h"
#include "third_party/blink/public/web/web_associated_url_loader.h"
#include "third_party/blink/public/platform/web_url_loader_client.h"
#include "third_party/blink/public/web/web_associated_url_loader_client.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/web/web_associated_url_loader_options.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_plugin_container.h"
#include "third_party/blink/public/web/web_plugin_params.h"
#include "third_party/blink/public/web/web_view.h"
#include "ui/gfx/geometry/rect.h"
#include "url/gurl.h"
#include "url/url_util.h"
#include <algorithm>

using blink::WebConsoleMessage;
// using blink::WebCookieJar;
// using blink::WebCursorInfo;
using blink::WebData;
using blink::WebFrame;
using blink::WebHTTPBody;
using blink::WebHTTPHeaderVisitor;
using blink::WebInputEvent;
using blink::WebInputEventResult;
using blink::WebKeyboardEvent;
using blink::WebLocalFrame;
using blink::WebMouseEvent;
using blink::WebPluginContainer;
using blink::WebPluginParams;
using blink::WebRect;
using blink::WebString;
using blink::WebURL;
using blink::WebURLError;
using blink::WebURLLoader;
using blink::WebAssociatedURLLoader;
using blink::WebAssociatedURLLoaderClient;
using blink::WebURLLoaderClient;
// using blink::WebURLLoaderOptions;
using blink::WebURLRequest;
using blink::WebURLResponse;
using blink::WebVector;
using blink::WebView;
using blink::WebSecurityOrigin;
using blink::CookieJar;

namespace content {

namespace {

// This class handles individual multipart responses. It is instantiated when
// we receive HTTP status code 206 in the HTTP response. This indicates
// that the response could have multiple parts each separated by a boundary
// specified in the response header.
#if 0
class MultiPartResponseClient : public WebURLLoaderClient {
 public:
  explicit MultiPartResponseClient(WebPluginResourceClient* resource_client)
      : byte_range_lower_bound_(0), resource_client_(resource_client) {}

  bool WillFollowRedirect(
                          // blink::WebURLLoader*,
                          const blink::WebURL& new_url,
                          const blink::WebURL& new_site_for_cookies,
                          const base::Optional<WebSecurityOrigin>& new_top_frame_origin,
                          const blink::WebString& new_referrer,
                          network::mojom::ReferrerPolicy new_referrer_policy,
                          const blink::WebString& new_method,
                          const blink::WebURLResponse& passed_redirect_response,
                          bool& report_raw_headers) override {
    return false;
  }

  void DidSendData(WebURLLoader*,
                   uint64_t,
                   uint64_t) override {}

  // Called when the multipart parser encounters an embedded multipart
  // response.
  void DidReceiveResponse(WebURLLoader*,
                          const WebURLResponse& response) override {
    int64_t byte_range_upper_bound, instance_size;
    if (!MultipartResponseDelegate::ReadContentRanges(
            response, &byte_range_lower_bound_, &byte_range_upper_bound,
            &instance_size)) {
      NOTREACHED();
    }
  }

  // Receives individual part data from a multipart response.
  void DidReceiveData(WebURLLoader*,
                      const char* data,
                      int data_length) override {
    // TODO(ananta)
    // We should defer further loads on multipart resources on the same lines
    // as regular resources requested by plugins to prevent reentrancy.
    resource_client_->DidReceiveData(data, data_length,
                                     byte_range_lower_bound_);
    byte_range_lower_bound_ += data_length;
  }

  void DidFinishLoading(
      blink::WebURLLoader*,
      base::TimeTicks finish_time,
      int64_t total_encoded_data_length,
      int64_t total_encoded_body_length,
      int64_t total_decoded_body_length,
      bool should_report_corb_blocking,
      const WebVector<network::cors::PreflightTimingInfo>&)override {}                        
  void DidFail(WebURLLoader*,
               const WebURLError&,
               int64_t total_encoded_data_length,
               int64_t total_encoded_body_length,
               int64_t total_decoded_body_length) override {}

 private:
  // The lower bound of the byte range.
  int64_t byte_range_lower_bound_;
  // The handler for the data.
  WebPluginResourceClient* resource_client_;
};
#endif

class MultiPartResponseClient : public WebAssociatedURLLoaderClient {
 public:
  explicit MultiPartResponseClient(WebPluginResourceClient* resource_client)
      : byte_range_lower_bound_(0), resource_client_(resource_client) {}

  bool WillFollowRedirect(const WebURL& new_url,
                                  const WebURLResponse& redirect_response) override {
    return false;
  }
  void DidSendData(uint64_t bytes_sent,
                           uint64_t total_bytes_to_be_sent) override {}
  void DidReceiveResponse(const WebURLResponse& response) {
    int64_t byte_range_upper_bound, instance_size;
    if (!MultipartResponseDelegate::ReadContentRanges(
            response, &byte_range_lower_bound_, &byte_range_upper_bound,
            &instance_size)) {
      NOTREACHED();
    }    
  }
  
  void DidReceiveData(const char* data, int data_length) override {
      resource_client_->DidReceiveData(data, data_length,
                                      byte_range_lower_bound_);
      byte_range_lower_bound_ += data_length;    
  }
  
  void DidFinishLoading() override {}
  void DidFail(const WebURLError&) override{}
  // Receives individual part data from a multipart response.
 private:
  // The lower bound of the byte range.
  int64_t byte_range_lower_bound_;
  // The handler for the data.
  WebPluginResourceClient* resource_client_;
};

class HeaderFlattener : public WebHTTPHeaderVisitor {
 public:
  explicit HeaderFlattener(std::string* buf) : buf_(buf) {}

  void VisitHeader(const WebString& name, const WebString& value) override {
    // TODO(darin): Should we really exclude headers with an empty value?
    if (!name.IsEmpty() && !value.IsEmpty()) {
      buf_->append(name.Utf8());
      buf_->append(": ");
      buf_->append(value.Utf8());
      buf_->append("\n");
    }
  }

 private:
  std::string* buf_;
};

std::string GetAllHeaders(const WebURLResponse& response) {
  // TODO(darin): It is possible for httpStatusText to be empty and still have
  // an interesting response, so this check seems wrong.
  std::string result;
  const WebString& status = response.HttpStatusText();
  if (status.IsEmpty())
    return result;

  // TODO(darin): Shouldn't we also report HTTP version numbers?
  result = base::StringPrintf("HTTP %d ", response.HttpStatusCode());
  result.append(status.Utf8());
  result.append("\n");

  HeaderFlattener flattener(&result);
  response.VisitHttpHeaderFields(&flattener);

  return result;
}

struct ResponseInfo {
  GURL url;
  std::string mime_type;
  uint32_t last_modified;
  uint32_t expected_length;
};

void GetResponseInfo(const WebURLResponse& response,
                     ResponseInfo* response_info) {
  response_info->url = response.ResponseUrl();
  response_info->mime_type = response.MimeType().Utf8();
  std::cout<<"-------[TODO]-----------GetResponseInfo:last_modified--------"<<std::endl;
  // Measured in seconds since 12:00 midnight GMT, January 1, 1970.
  // response_info->last_modified =
  //     static_cast<uint32_t>(response.LastModifiedDate());

  // If the length comes in as -1, then it indicates that it was not
  // read off the HTTP headers. We replicate Safari webkit behavior here,
  // which is to set it to 0.
  response_info->expected_length =
      static_cast<uint32_t>(std::max(response.ExpectedContentLength(), 0L));

  WebString content_encoding =
      response.HttpHeaderField(WebString::FromUTF8("Content-Encoding"));
  if (!content_encoding.IsNull() &&
      !base::EqualsASCII(base::StringPiece16(content_encoding.Utf16()),
                         "identity")) {
    // Don't send the compressed content length to the plugin, which only
    // cares about the decoded length.
    response_info->expected_length = 0;
  }
}

}  // namespace

// blink::WebPlugin ----------------------------------------------------------

// struct WebPluginImpl::ClientInfo {
//   unsigned long id;
//   WebPluginResourceClient* client;
//   blink::WebURLRequest request;
//   bool pending_failure_notification;
//   // linked_ptr<blink::WebURLLoader> loader;
//   linked_ptr<blink::WebAssociatedURLLoader> loader;
//   bool notify_redirects;
//   bool is_plugin_src_load;
//   int64_t data_offset;
// };

bool WebPluginImpl::Initialize(WebPluginContainer* container) {

  LOG(WARNING) << "renderer process contains plugin, pid is  :  " << base::GetCurrentProcId();

  if (!render_view_.get()) {
    LOG(ERROR) << "No RenderView";
    return false;
  }

  WebPluginDelegateProxy* plugin_delegate =
      new WebPluginDelegateProxy(this, mime_type_, render_view_, render_frame_);

  // Store the plugin's unique identifier, used by the container to track its
  // script objects.
  npp_ = plugin_delegate->GetPluginNPP();

  // Set the container before Initialize because the plugin may
  // synchronously call NPN_GetValue to get its container, or make calls
  // passing script objects that need to be tracked, during initialization.
  SetContainer(container);

  bool ok = plugin_delegate->Initialize(plugin_url_, arg_names_, arg_values_,
                                        load_manually_);
  if (!ok) {
    plugin_delegate->PluginDestroyed();

    blink::WebPlugin* replacement_plugin =
        GetContentClient()->renderer()->CreatePluginReplacement(render_frame_,
                                                                file_path_);
    if (!replacement_plugin) {
      // Maintain invariant that container() returns null when initialize()
      // returns false.
      SetContainer(nullptr);
      return false;
    }

    // Disable scripting by this plugin before replacing it with the new
    // one. This plugin also needs destroying, so use destroy(), which will
    // implicitly disable scripting while un-setting the container.
    Destroy();

    // Inform the container of the replacement plugin, then initialize it.
    container->SetPlugin(replacement_plugin);
    return replacement_plugin->Initialize(container);
  }

  delegate_ = plugin_delegate;

  return true;
}

void WebPluginImpl::Destroy() {
  SetContainer(NULL);
  base::ThreadTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, this);
}

NPObject* WebPluginImpl::ScriptableObject() {
  if (!delegate_)
    return NULL;

  return delegate_->GetPluginScriptableObject();
}

NPP WebPluginImpl::PluginNPP() {
  return npp_;
}

bool WebPluginImpl::GetFormValue(blink::WebString& value) {
  if (!delegate_)
    return false;
  base::string16 form_value;
  if (!delegate_->GetFormValue(&form_value))
    return false;
  value = blink::WebString(form_value.data(), form_value.length());
  return true;
}

// void WebPluginImpl::LayoutIfNeeded() {
//   if (!container_)
//     return;

// }

void WebPluginImpl::Paint(cc::PaintCanvas* canvas,
                          const blink::WebRect& paint_rect) {
  if (!delegate_ || !container_)
    return;

  // Note that |canvas| is only used when in windowless mode.
  delegate_->Paint(canvas, paint_rect);
}

void WebPluginImpl::UpdateGeometry(const WebRect& window_rect,
                                   const WebRect& clip_rect,
                                   const WebRect& unobscured_rect,      
                                   bool is_visible) {
  WebPluginGeometry new_geometry;
  new_geometry.window = window_;
  new_geometry.window_rect = window_rect;
  new_geometry.clip_rect = clip_rect;
  new_geometry.visible = is_visible;
  new_geometry.rects_valid = true;

  if (window_) {
     // (wangjuna:) even new_geometry is same as geometry_, always let plugin move, for bug#57659,2020-12-11
    LOG(INFO) << "[NPAPI] WebPluginImpl::UpdateGeometry -> SchedulePluginMove";
    render_frame_->GetLocalRootRenderWidget()->SchedulePluginMove(new_geometry);
  }

  // We invalidate windowed plugins during the first geometry update to
  // ensure that they get reparented to the wrapper window in the browser.
  // This ensures that they become visible and are painted by the OS. This is
  // required as some pages don't invalidate when the plugin is added.
  if (first_geometry_update_ && window_) {
    LOG(INFO) << "[NPAPI] UpdateGeometry::InvalidateRect";
    InvalidateRect(window_rect);
  }

  // Only UpdateGeometry if either the window or clip rects have changed.
  if (delegate_ && (first_geometry_update_ ||
                    new_geometry.window_rect != geometry_.window_rect ||
                    new_geometry.clip_rect != geometry_.clip_rect)) {
    // Notify the plugin that its parameters have changed.
    delegate_->UpdateGeometry(new_geometry.window_rect, new_geometry.clip_rect);
  }

  // Initiate a download on the plugin url. This should be done for the
  // first update geometry sequence. We need to ensure that the plugin
  // receives the geometry update before it starts receiving data.
  if (first_geometry_update_) {
    // An empty url corresponds to an EMBED tag with no src attribute.
    if (!load_manually_ && plugin_url_.is_valid()) {
      // The Flash plugin hangs for a while if it receives data before
      // receiving valid plugin geometry. By valid geometry we mean the
      // geometry received by a call to setFrameRect in the Webkit
      // layout code path. To workaround this issue we download the
      // plugin source url on a timer.
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&WebPluginImpl::OnDownloadPluginSrcUrl,
                                weak_factory_.GetWeakPtr()));
    }
  }

#if defined(OS_WIN)
  // Don't cache the geometry during the first geometry update. The first
  // geometry update sequence is received when Widget::setParent is called.
  // For plugins like media player which have a bug where they only honor
  // the first geometry update, we have a quirk which ignores the first
  // geometry update. To ensure that these plugins work correctly in cases
  // where we receive only one geometry update from webkit, we also force
  // a geometry update during paint which should go out correctly as the
  // initial geometry update was not cached.
  if (!first_geometry_update_)
    geometry_ = new_geometry;
#else   // OS_WIN
  geometry_ = new_geometry;
#endif  // OS_WIN

  first_geometry_update_ = false;
}

void WebPluginImpl::UpdateFocus(bool focused, blink::mojom::FocusType focus_type) {
  if (accepts_input_events_)
    delegate_->SetFocus(focused);
}

void WebPluginImpl::UpdateVisibility(bool visible) {
  //@wangjun: refer to PepperWebPluginImpl::UpdateVisibility, maybe this function should do nothing.
  //also for fix bug#54935
  LOG(INFO) << "[NPAPI] WebPluginImpl::UpdateVisibility " << visible;
#if defined(USE_UNIONTECH_NPAPI)
  if (!window_)
    return;

  WebPluginGeometry move;
  move.window = window_;
  move.window_rect = gfx::Rect();
  move.clip_rect = gfx::Rect();
  move.rects_valid = false;
  move.visible = visible;

  render_frame_->GetLocalRootRenderWidget()->SchedulePluginMove(move);
#endif
}

bool WebPluginImpl::AcceptsInputEvents() {
  return accepts_input_events_;
}

WebInputEventResult WebPluginImpl::HandleInputEvent(
    const blink::WebCoalescedInputEvent& event,
    ui::Cursor* cursor_info) {
  // Swallow context menu events in order to suppress the default context menu.
  if (event.Event().GetType() == WebInputEvent::kContextMenu)
    return WebInputEventResult::kHandledSuppressed;

  ui::Cursor web_cursor_info;
  bool ret = delegate_->HandleInputEvent(event.Event(), &web_cursor_info);
  *cursor_info = web_cursor_info;
  // cursor_info.type = web_cursor_info.type;
  // cursor_info.hot_spot = web_cursor_info.hotspot;
  // cursor_info.custom_image = web_cursor_info.custom_image;
  // cursor_info.image_scale_factor = web_cursor_info.image_scale_factor;
  return ret ? WebInputEventResult::kHandledApplication
             : WebInputEventResult::kNotHandled;
}

void WebPluginImpl::DidReceiveResponse(const WebURLResponse& response) {
  ignore_response_error_ = false;

  ResponseInfo response_info;
  GetResponseInfo(response, &response_info);

  delegate_->DidReceiveManualResponse(
      response_info.url, response_info.mime_type, GetAllHeaders(response),
      response_info.expected_length, response_info.last_modified);
}

void WebPluginImpl::DidReceiveData(const char* data, size_t data_length) {
  delegate_->DidReceiveManualData(data, data_length);
}

void WebPluginImpl::DidFinishLoading() {
  delegate_->DidFinishManualLoading();
}

void WebPluginImpl::DidFailLoading(const WebURLError& error) {
  if (!ignore_response_error_)
    delegate_->DidManualLoadFail();
}

void WebPluginImpl::DidFinishLoadingFrameRequest(const WebURL& url,
                                                 void* notify_data) {
  if (delegate_) {
    // We're converting a void* into an arbitrary int id.  Though
    // these types are the same size on all the platforms we support,
    // the compiler may complain as though they are different, so to
    // make the casting gods happy go through an intptr_t (the union
    // of void* and int) rather than converting straight across.
    delegate_->DidFinishLoadWithReason(url, NPRES_DONE,
                                       reinterpret_cast<intptr_t>(notify_data));
  }
}

void WebPluginImpl::DidFailLoadingFrameRequest(const WebURL& url,
                                               void* notify_data,
                                               const WebURLError& error) {
  if (!delegate_)
    return;

  NPReason reason =
      error.reason() == net::ERR_ABORTED ? NPRES_USER_BREAK : NPRES_NETWORK_ERR;
  // See comment in didFinishLoadingFrameRequest about the cast here.
  delegate_->DidFinishLoadWithReason(url, reason,
                                     reinterpret_cast<intptr_t>(notify_data));
}

bool WebPluginImpl::IsPlaceholder() {
  return false;
}

bool WebPluginImpl::IsNPPlugin() {
  return true;
}

///
///
/// UosLoaderClient----------------------------------------------------------------

WebPluginImpl::UosLoaderClient::UosLoaderClient(WebPluginImpl* parent)
        : parent_(parent) {}

bool WebPluginImpl::UosLoaderClient::WillFollowRedirect(const WebURL& new_url,
                                  const WebURLResponse& redirect_response)
{
    parent_->WillFollowRedirect(new_url, redirect_response);
}

void WebPluginImpl::UosLoaderClient::DidSendData(uint64_t bytes_sent,
                           uint64_t total_bytes_to_be_sent){
    parent_->SendData(bytes_sent, total_bytes_to_be_sent);                      
}

void WebPluginImpl::UosLoaderClient::DidReceiveResponse(const WebURLResponse& responses) {
    parent_->ReceiveResponse(responses); 
}

void WebPluginImpl::UosLoaderClient::DidReceiveData(const char* data, int data_length){
    parent_->ReceiveData(data, data_length);  
}

void WebPluginImpl::UosLoaderClient::DidReceiveCachedMetadata(const char* data, int data_length){
    parent_->ReceiveData(data, data_length); 
}

void WebPluginImpl::UosLoaderClient::DidFinishLoading(){
    parent_->FinishLoading(); 
}
void WebPluginImpl::UosLoaderClient::DidFail(const WebURLError& error) {
    parent_->Fail(error); 
}

///-----------------------------------------------------------------------------------






///
///
/// LoaderClient---------------------------------------------------------------------------------------
#if 0
WebPluginImpl::LoaderClient::LoaderClient(WebPluginImpl* parent)
    : parent_(parent) {}

bool WebPluginImpl::LoaderClient::WillFollowRedirect(    
    // blink::WebURLLoader* loader,
    const blink::WebURL& new_url,
    const blink::WebURL& new_site_for_cookies,
    const base::Optional<blink::WebSecurityOrigin>& new_top_frame_origin,
    const blink::WebString& new_referrer,
    network::mojom::ReferrerPolicy new_referrer_policy,
    const blink::WebString& new_method,
    const blink::WebURLResponse& passed_redirect_response,
    bool& report_raw_headers) {
  std::cout<<"------------------[TODO]---WebPluginImpl::LoaderClient::WillFollowRedirect----"<<std::endl;
  // parent_->WillFollowRedirect(loader, new_url, new_site_for_cookies,
  //                             new_referrer, new_referrer_policy, new_method,
  //                             passed_redirect_response, report_raw_headers);                          
  return false;
}

void WebPluginImpl::LoaderClient::DidSendData(
    blink::WebURLLoader* loader,
    uint64_t bytes_sent,
    uint64_t total_bytes_to_be_sent) {
  parent_->DidSendData(loader, bytes_sent, total_bytes_to_be_sent);
}

void WebPluginImpl::LoaderClient::DidReceiveResponse(
    blink::WebURLLoader* loader,
    const blink::WebURLResponse& response) {
  parent_->DidReceiveResponse(loader, response);
}

// void WebPluginImpl::LoaderClient::DidDownloadData(blink::WebURLLoader* loader,
//                                                   int data_length,
//                                                   int encoded_data_length) {}

void WebPluginImpl::LoaderClient::DidReceiveData(blink::WebURLLoader* loader,
                                                 const char* data,
                                                 int data_length) {
  parent_->DidReceiveData(loader, data, data_length, data_length);
}

void WebPluginImpl::LoaderClient::DidReceiveCachedMetadata(
    blink::WebURLLoader* loader,
    const char* data,
    int data_length) {}

void WebPluginImpl::LoaderClient::DidFinishLoading(
    blink::WebURLLoader* loader,
    base::TimeTicks finish_time,
    int64_t total_encoded_data_length,
    int64_t total_encoded_body_length,
    int64_t total_decoded_body_length,
    bool should_report_corb_blocking,
    const WebVector<network::cors::PreflightTimingInfo>& info) {
  parent_->DidFinishLoading(
      loader, finish_time, total_encoded_data_length,
      total_encoded_body_length, total_decoded_body_length,
      should_report_corb_blocking);
}

void WebPluginImpl::LoaderClient::DidFail(blink::WebURLLoader* loader,
                                          const blink::WebURLError& error,
                                          int64_t total_encoded_data_length,
                                          int64_t total_encoded_body_length,
                                          int64_t total_decoded_body_length) {
  parent_->DidFail(loader, error);
}
#endif
// -----------------------------------------------------------------------------

WebPluginImpl::WebPluginImpl(WebFrame* webframe,
                             const WebPluginParams& params,
                             const base::FilePath& file_path,
                             const base::WeakPtr<RenderViewImpl>& render_view,
                             RenderFrameImpl* render_frame)
    : windowless_(false),
      window_(gfx::kNullAcceleratedWidget),
      accepts_input_events_(false),
      render_frame_(render_frame),
      render_view_(render_view),
      webframe_(webframe),
      delegate_(NULL),
      container_(NULL),
      npp_(NULL),
      plugin_url_(params.url),
      load_manually_(params.load_manually),
      first_geometry_update_(true),
      ignore_response_error_(false),
      file_path_(file_path),
      mime_type_(base::ToLowerASCII(
          base::UTF16ToASCII(base::StringPiece16(params.mime_type.Utf16())))),
      loader_client_(this),
      weak_factory_(this) {
  DCHECK_EQ(params.attribute_names.size(), params.attribute_values.size());

  for (size_t i = 0; i < params.attribute_names.size(); ++i) {
    arg_names_.push_back(params.attribute_names[i].Utf8());
    arg_values_.push_back(params.attribute_values[i].Utf8());
  }

  // Set subresource URL for crash reporting.
  static auto* crash_key = base::debug::AllocateCrashKeyString(
      "subresource_url", base::debug::CrashKeySize::Size32);
  base::debug::SetCrashKeyString(crash_key, plugin_url_.spec());
  base::debug::ClearCrashKeyString(crash_key);
}

WebPluginImpl::~WebPluginImpl() {}

void WebPluginImpl::SetWindow(gfx::PluginWindowHandle window) {
  if (window) {
    DCHECK(!windowless_);
    window_ = window;
#if defined(OS_MACOSX)
    // TODO(kbr): remove. http://crbug.com/105344

    // Lie to ourselves about being windowless even if we got a fake
    // plugin window handle, so we continue to get input events.
    windowless_ = true;
    accepts_input_events_ = true;
    // We do not really need to notify the page delegate that a plugin
    // window was created -- so don't.
#else
    accepts_input_events_ = false;

#if defined(USE_X11)
    // Tell the view delegate that the plugin window was created, so that it
    // can create necessary container widgets.
    
    render_frame_->Send(new ViewHostMsg_CreatePluginContainer(
      render_frame_->GetLocalRootRenderWidget()->routing_id(), window));      
#endif  // USE_X11

#endif  // OS_MACOSX
  } else {
    DCHECK(!window_);  // Make sure not called twice.
    windowless_ = true;
    accepts_input_events_ = true;
  }
}

void WebPluginImpl::SetAcceptsInputEvents(bool accepts) {
  accepts_input_events_ = accepts;
}

void WebPluginImpl::WillDestroyWindow(gfx::PluginWindowHandle window) {
  DCHECK_EQ(window, window_);
  window_ = gfx::kNullPluginWindow;
  if (render_view_.get()) {
#if defined(USE_X11)
    render_frame_->Send(new ViewHostMsg_DestroyPluginContainer(
        render_frame_->GetLocalRootRenderWidget()->routing_id(), window));
#endif
    // render_frame_->GetRenderView()->CleanupWindowInPluginMoves(window);
    // render_view_->GetWidget()->CleanupWindowInPluginMoves(window);
    render_frame_->GetLocalRootRenderWidget()->CleanupWindowInPluginMoves(window);
  }
}

GURL WebPluginImpl::CompleteURL(const char* url) {
  if (!webframe_) {
    NOTREACHED();
    return GURL();
  }
  // TODO(darin): Is conversion from UTF8 correct here?
  blink::WebDocument document =
      webframe_->IsWebLocalFrame() ? webframe_->ToWebLocalFrame()->GetDocument()
                                   : blink::WebDocument();
  return document.CompleteURL(WebString::FromUTF8(url));
}

void WebPluginImpl::CancelResource(unsigned long id) {
  ///-------[FIX] FIX BY HWB
  // for (size_t i = 0; i < clients_.size(); ++i) {
  //   if (clients_[i].id == id) {
  //     if (clients_[i].loader.get()) {
  //       clients_[i].loader->SetDefersLoading(false);
  //       std::cout<<"---------[TODO]----WebPluginImpl::CancelResource---"<<std::endl;
  //       clients_[i].loader->Cancel();
  //       RemoveClient(i);
  //     }
  //     return;
  //   }
  // }

    if (clientInfo_.id == id) {
        if (clientInfo_.loader.get()) {
          clientInfo_.loader->SetDefersLoading(false);        
          clientInfo_.loader->Cancel();        
        }  
    }
}

bool WebPluginImpl::SetPostData(WebURLRequest* request,
                                const char* buf,
                                uint32_t length) {
  std::vector<std::string> names;
  std::vector<std::string> values;
  std::vector<char> body;
  bool rv = PluginHost::SetPostData(buf, length, &names, &values, &body);

  for (size_t i = 0; i < names.size(); ++i) {
    request->AddHttpHeaderField(WebString::FromUTF8(names[i]),
                                WebString::FromUTF8(values[i]));
  }

  WebString content_type_header = WebString::FromUTF8("Content-Type");
  const WebString& content_type = request->HttpHeaderField(content_type_header);
  if (content_type.IsEmpty()) {
    request->SetHttpHeaderField(
        content_type_header,
        WebString::FromUTF8("application/x-www-form-urlencoded"));
  }

  WebHTTPBody http_body;
  if (body.size()) {
    http_body.Initialize();
    http_body.AppendData(WebData(&body[0], body.size()));
  }
  request->SetHttpBody(http_body);

  return rv;
}

bool WebPluginImpl::IsValidUrl(const GURL& url, ReferrerValue referrer_flag) {
  if (referrer_flag == PLUGIN_SRC && mime_type_ == kFlashPluginSwfMimeType &&
      url.GetOrigin() != plugin_url_.GetOrigin()) {
    // Do url check to make sure that there are no @, ;, \ chars in between url
    // scheme and url path.
    const char* url_to_check(url.spec().data());
    url::Parsed parsed;
    url::ParseStandardURL(url_to_check, strlen(url_to_check), &parsed);
    if (parsed.path.begin <= parsed.scheme.end())
      return true;
    std::string string_to_search;
    string_to_search.assign(url_to_check + parsed.scheme.end(),
                            parsed.path.begin - parsed.scheme.end());
    if (string_to_search.find("@") != std::string::npos ||
        string_to_search.find(";") != std::string::npos ||
        string_to_search.find("\\") != std::string::npos)
      return false;
  }

  return true;
}

WebPluginImpl::RoutingStatus WebPluginImpl::RouteToFrame(
    const char* url,
    bool is_javascript_url,
    bool popups_allowed,
    const char* method,
    const char* target,
    const char* buf,
    unsigned int len,
    int notify_id,
    ReferrerValue referrer_flag) {
  // If there is no target, there is nothing to do
  if (!target)
    return NOT_ROUTED;

  // This could happen if the WebPluginContainer was already deleted.
  if (!webframe_)
    return NOT_ROUTED;

  WebString target_str = WebString::FromUTF8(target);

  // Take special action for JavaScript URLs
  if (is_javascript_url && webframe_->IsWebLocalFrame()) {
    WebLocalFrame* frame = webframe_->ToWebLocalFrame();
    if (frame) {
      WebFrame* target_frame = frame->FindFrameByName(target_str);
      // For security reasons, do not allow JavaScript on frames
      // other than this frame.
      if (target_frame != webframe_) {
        // TODO(darin): Localize this message.
        const char kMessage[] =
            "Ignoring cross-frame javascript URL load requested by plugin.";
        frame->AddMessageToConsole(WebConsoleMessage(
            blink::mojom::ConsoleMessageLevel::kError, WebString::FromUTF8(kMessage)));
        return ROUTED;
      }
    }

    // Route javascript calls back to the plugin.
    return NOT_ROUTED;
  }

  // If we got this far, we're routing content to a target frame.
  // Go fetch the URL.

  GURL complete_url = CompleteURL(url);
  // Remove when flash bug is fixed. http://crbug.com/40016.
  if (!WebPluginImpl::IsValidUrl(complete_url, referrer_flag))
    return INVALID_URL;

  if (strcmp(method, "GET") != 0) {
    // We're only going to route HTTP/HTTPS requests
    if (!complete_url.SchemeIsHTTPOrHTTPS())
      return INVALID_URL;
  }

  WebURLRequest request(complete_url);
  SetReferrer(&request, referrer_flag);

  blink::WebDocument document =
      webframe_->IsWebLocalFrame() ? webframe_->ToWebLocalFrame()->GetDocument()
                                   : blink::WebDocument();
  request.SetHttpMethod(WebString::FromUTF8(method));
  request.SetSiteForCookies(document.SiteForCookies());
  request.SetHasUserGesture(popups_allowed);
  // ServiceWorker is disabled for NPAPI.
  request.SetSkipServiceWorker(true);
  if (len > 0) {
    if (!SetPostData(&request, buf, len)) {
      // Uhoh - we're in trouble.  There isn't a good way
      // to recover at this point.  Break out.
      NOTREACHED();
      return ROUTED;
    }
  }

  container_->LoadFrameRequest(request, target_str, notify_id != 0,
                               reinterpret_cast<void*>(notify_id));
  return ROUTED;
}

NPObject* WebPluginImpl::GetWindowScriptNPObject() {
  if (!webframe_) {
    NOTREACHED();
    return NULL;
  }
  return webframe_->windowObject();
}

NPObject* WebPluginImpl::GetPluginElement() {
  return container_->ScriptableObjectForElement();
}

bool WebPluginImpl::FindProxyForUrl(const GURL& url, std::string* proxy_list) {
  // Proxy resolving doesn't work in single-process mode.
  return false;
}

void WebPluginImpl::SetCookie(const GURL& url,
                              const GURL& first_party_for_cookies,
                              const std::string& cookie) {
  std::cout<<"--------------------[TODO]-------WebPluginImpl::SetCookie"<<std::endl;                                
  // if (!render_view_.get())
  //   return;

  // CookieJar* cookie_jar = render_frame_->CookieJar();
  // if (!cookie_jar) {
  //   DLOG(WARNING) << "No cookie jar!";
  //   return;
  // }

  // cookie_jar->SetCookie(url, first_party_for_cookies,
  //                       WebString::FromUTF8(cookie));
}

std::string WebPluginImpl::GetCookies(const GURL& url,
                                      const GURL& first_party_for_cookies) {
std::cout<<"--------------------[TODO]-------WebPluginImpl::GetCookies"<<std::endl;    
return std::string();                                    
  // if (!render_view_.get())
  //   return std::string();

  // CookieJar* cookie_jar = render_frame_->CookieJar();
  // if (!cookie_jar) {
  //   DLOG(WARNING) << "No cookie jar!";
  //   return std::string();
  // }

  // return base::UTF16ToUTF8(base::StringPiece16(
  //     cookie_jar->Cookies(url, first_party_for_cookies).Utf16()));
}

void WebPluginImpl::URLRedirectResponse(bool allow, int resource_id) {
  ///--------[FIX]---------FIX BY HWB
  // for (size_t i = 0; i < clients_.size(); ++i) {
  //   if (clients_[i].id == static_cast<unsigned long>(resource_id)) {
  //     if (clients_[i].loader.get()) {
  //       if (allow) {
  //         clients_[i].loader->SetDefersLoading(false);
  //       } else {
  //         std::cout<<"---------[TODO]----WebPluginImpl::URLRedirectResponse---"<<std::endl;
  //         // clients_[i].loader->Cancel();
  //         if (clients_[i].client)
  //           clients_[i].client->DidFail(clients_[i].id);
  //       }
  //     }
  //     break;
  //   }
  // }
    if (clientInfo_.id == static_cast<unsigned long>(resource_id)) {
        if (clientInfo_.loader.get()) {
            if (allow) {
              clientInfo_.loader->SetDefersLoading(false);
            } else {
              std::cout<<"---------[TODO]----WebPluginImpl::URLRedirectResponse---"<<std::endl;
              clientInfo_.loader->Cancel();
              if (clientInfo_.client)
                clientInfo_.client->DidFail(clientInfo_.id);
            }
        }        
    }  
}

bool WebPluginImpl::CheckIfRunInsecureContent(const GURL& url) {
  if (!webframe_)
    return true;

  return webframe_->checkIfRunInsecureContent(url);
}

#if defined(OS_MACOSX)
WebPluginAcceleratedSurface* WebPluginImpl::GetAcceleratedSurface(
    gfx::GpuPreference gpu_preference) {
  return NULL;
}

void WebPluginImpl::AcceleratedPluginEnabledRendering() {}

void WebPluginImpl::AcceleratedPluginAllocatedIOSurface(int32 width,
                                                        int32 height,
                                                        uint32_t surface_id) {
  next_io_surface_allocated_ = true;
  next_io_surface_width_ = width;
  next_io_surface_height_ = height;
  next_io_surface_id_ = surface_id;
}

void WebPluginImpl::AcceleratedPluginSwappedIOSurface() {
  if (!container_)
    return;
  // Deferring the call to setBackingIOSurfaceId is an attempt to
  // work around garbage occasionally showing up in the plugin's
  // area during live resizing of Core Animation plugins. The
  // assumption was that by the time this was called, the plugin
  // process would have populated the newly allocated IOSurface. It
  // is not 100% clear at this point why any garbage is getting
  // through. More investigation is needed. http://crbug.com/105346
  if (next_io_surface_allocated_) {
    if (next_io_surface_id_) {
      if (!io_surface_layer_.get()) {
        io_surface_layer_ =
            cc::IOSurfaceLayer::Create(cc_blink::WebLayerImpl::LayerSettings());
        web_layer_.reset(new cc_blink::WebLayerImpl(io_surface_layer_));
        container_->setWebLayer(web_layer_.get());
      }
      io_surface_layer_->SetIOSurfaceProperties(
          next_io_surface_id_,
          gfx::Size(next_io_surface_width_, next_io_surface_height_));
    } else {
      container_->setWebLayer(NULL);
      web_layer_.reset();
      io_surface_layer_ = NULL;
    }
    next_io_surface_allocated_ = false;
  } else {
    if (io_surface_layer_.get())
      io_surface_layer_->SetNeedsDisplay();
  }
}
#endif

void WebPluginImpl::Invalidate() {
  if (container_)
    container_->Invalidate();
}

void WebPluginImpl::InvalidateRect(const gfx::Rect& rect) {
  if (container_)
    container_->InvalidateRect(rect);
}

void WebPluginImpl::OnDownloadPluginSrcUrl() {
  HandleURLRequestInternal(plugin_url_.spec().c_str(), "GET", NULL, NULL, 0, 0,
                           false, DOCUMENT_URL, false, true);
}

WebPluginResourceClient* WebPluginImpl::GetClientFromLoader(
    WebURLLoader* loader) {
  ClientInfo* client_info = GetClientInfoFromLoader(loader);
  if (client_info)
    return client_info->client;
  return NULL;
}

WebPluginImpl::ClientInfo* WebPluginImpl::GetClientInfoFromLoader(
    WebURLLoader* loader) {
  // for (size_t i = 0; i < clients_.size(); ++i) {
  //   if (clients_[i].loader.get() == loader)
  //     return &clients_[i];
  // }

  NOTREACHED();
  return 0;
}

void WebPluginImpl::WillFollowRedirect(const WebURL& new_url,
                                  const WebURLResponse& redirect_response){

    // Currently this check is just to catch an https -> http redirect when
    // loading the main plugin src URL. Longer term, we could investigate
    // firing mixed diplay or scripting issues for subresource loads
    // initiated by plugins.
    if (clientInfo_.is_plugin_src_load && webframe_ &&
        !webframe_->checkIfRunInsecureContent(new_url)) {      
        clientInfo_.loader->Cancel();
        clientInfo_.client->DidFail(clientInfo_.id);
        return;
    }
    if (net::HttpResponseHeaders::IsRedirectResponseCode(
            redirect_response.HttpStatusCode())) {
      // If the plugin does not participate in url redirect notifications then
      // just block cross origin 307 POST redirects.
        if (!clientInfo_.notify_redirects) {
            if (redirect_response.HttpStatusCode() == 307 ){//&&
                std::cout<<"----------[TODO]----WebPluginImpl::WillFollowRedirect"<<std::endl;
                // base::LowerCaseEqualsASCII(new_method.Utf8(), "post")) {
              GURL original_request_url(redirect_response.ResponseUrl());
              GURL response_url(new_url);
                if (original_request_url.GetOrigin() != response_url.GetOrigin()) {
                  clientInfo_.loader->SetDefersLoading(true);            
                  clientInfo_.loader->Cancel();
                  clientInfo_.client->DidFail(clientInfo_.id);
                  return;
                }
            }
        } else {
          clientInfo_.loader->SetDefersLoading(true);
        }
    }
    clientInfo_.client->WillSendRequest(new_url, redirect_response.HttpStatusCode());
}


void WebPluginImpl::SendData(uint64_t  bytes_sent,
                 uint64_t total_bytes_to_be_sent) {

}

void WebPluginImpl::ReceiveResponse(const WebURLResponse& response) {
    // TODO(jam): THIS LOGIC IS COPIED IN PluginURLFetcher::OnReceivedResponse
    // until kDirectNPAPIRequests is the default and we can remove this old path.
    static const int kHttpPartialResponseStatusCode = 206;
    static const int kHttpResponseSuccessStatusCode = 200;

    // WebPluginResourceClient* client = GetClientFromLoader(loader);
    WebPluginResourceClient* client = clientInfo_.client;
    if (!client)
        return;

    ResponseInfo response_info;
    GetResponseInfo(response, &response_info);
    // ClientInfo* loader_client_info = GetClientInfoFromLoader(loader);
    // if (!loader_client_info)
    //   return;

    bool request_is_seekable = true;
    if (client->IsMultiByteResponseExpected()) {
        if (response.HttpStatusCode() == kHttpPartialResponseStatusCode) {
          // ClientInfo* client_info = GetClientInfoFromLoader(loader);
          // if (!client_info)
          //   return;
          if (HandleHttpMultipartResponse(response, client)) {
            // Multiple ranges requested, data will be delivered by
            // MultipartResponseDelegate.
            clientInfo_.data_offset = 0;
            return;
          }
          int64_t upper_bound = 0, instance_size = 0;
          // Single range requested - go through original processing for
          // non-multipart requests, but update data offset.
          MultipartResponseDelegate::ReadContentRanges(
              response, &clientInfo_.data_offset, &upper_bound, &instance_size);
        } else if (response.HttpStatusCode() == kHttpResponseSuccessStatusCode) {
          RenderThread::Get()->RecordAction(
              base::UserMetricsAction("Plugin_200ForByteRange"));
          // If the client issued a byte range request and the server responds with
          // HTTP 200 OK, it indicates that the server does not support byte range
          // requests.
          // We need to emulate Firefox behavior by doing the following:-
          // 1. Destroy the plugin instance in the plugin process. Ensure that
          //    existing resource requests initiated for the plugin instance
          //    continue to remain valid.
          // 2. Create a new plugin instance and notify it about the response
          //    received here.
          // if (!ReinitializePluginForResponse(loader)) {
          if (!ReinitializePluginForResponse()) {        
            NOTREACHED();
            return;
          }

          // The server does not support byte range requests. No point in creating
          // seekable streams.
          request_is_seekable = false;

          delete client;
          client = NULL;

          // Create a new resource client for this request.
          // for (size_t i = 0; i < clients_.size(); ++i) {
          //   if (clients_[i].loader.get() == loader) {
          //     WebPluginResourceClient* resource_client =
          //         delegate_->CreateResourceClient(clients_[i].id, plugin_url_, 0);
          //     clients_[i].client = resource_client;
          //     client = resource_client;
          //     break;
          //   }
          // }

          WebPluginResourceClient* resource_client =
          delegate_->CreateResourceClient(clientInfo_.id, plugin_url_, 0);
          clientInfo_.client = resource_client;  
          client = resource_client;  
        }
    }

    // Calling into a plugin could result in reentrancy if the plugin yields
    // control to the OS like entering a modal loop etc. Prevent this by
    // stopping further loading until the plugin notifies us that it is ready to
    // accept data
    // loader->SetDefersLoading(true);
    clientInfo_.loader->SetDefersLoading(true);

    client->DidReceiveResponse(response_info.mime_type, GetAllHeaders(response),
                                response_info.expected_length,
                                response_info.last_modified, request_is_seekable);

    // Bug http://b/issue?id=925559. The flash plugin would not handle the HTTP
    // error codes in the stream header and as a result, was unaware of the
    // fate of the HTTP requests issued via NPN_GetURLNotify. Webkit and FF
    // destroy the stream and invoke the NPP_DestroyStream function on the
    // plugin if the HTTP request fails.
    const GURL& url = response.ResponseUrl();
    if (url.SchemeIs(url::kHttpScheme) || url.SchemeIs(url::kHttpsScheme)) {
        if (response.HttpStatusCode() < 100 || response.HttpStatusCode() >= 400) {
        // The plugin instance could be in the process of deletion here.
        // Verify if the WebPluginResourceClient instance still exists before
        // use.      
        // ClientInfo* info = GetClientInfoFromLoader(loader);
        // if (info) {
        //   info->pending_failure_notification = true;
        // }
            clientInfo_.pending_failure_notification = true;
        }
    }
}
  // void DidDownloadData(uint64_t data_length);
void WebPluginImpl::ReceiveData(const char* data, int data_length){
      // WebPluginResourceClient* client = GetClientFromLoader(loader);
    WebPluginResourceClient* client = clientInfo_.client;
    if (!client)
      return;

    MultiPartResponseHandlerMap::iterator index =
    multi_part_response_map_.find(client);
    if (index != multi_part_response_map_.end()) {
        MultipartResponseDelegate* multi_part_handler = (*index).second;
        DCHECK(multi_part_handler != NULL);
        multi_part_handler->OnReceivedData(data, data_length, data_length);
      } else {
        clientInfo_.loader->SetDefersLoading(true);
        // ClientInfo* client_info = GetClientInfoFromLoader(loader);
        client->DidReceiveData(data, data_length, clientInfo_.data_offset);
        clientInfo_.data_offset += data_length;
    }
}
  // void DidReceiveCachedMetadata(const char* data, int data_length);
  
void WebPluginImpl::FinishLoading() {
  ///-------[FIX] FIX BY HWB
  // ClientInfo* client_info = GetClientInfoFromLoader(loader);
    if (clientInfo_.client) {
      MultiPartResponseHandlerMap::iterator index =
          multi_part_response_map_.find(clientInfo_.client);
      if (index != multi_part_response_map_.end()) {
        delete (*index).second;
        multi_part_response_map_.erase(index);
        DidStopLoading();
      }
      clientInfo_.loader->SetDefersLoading(true);
      WebPluginResourceClient* resource_client = clientInfo_.client;
      // The ClientInfo can get deleted in the call to DidFinishLoading below.
      // It is not safe to access this structure after that.
      clientInfo_.client = NULL;
      resource_client->DidFinishLoading(clientInfo_.id);
    }
}

void WebPluginImpl::Fail(const WebURLError&){
    if (clientInfo_.client) {
      clientInfo_.loader->SetDefersLoading(true);
      WebPluginResourceClient* resource_client = clientInfo_.client;
      // The ClientInfo can get deleted in the call to DidFail below.
      // It is not safe to access this structure after that.
      clientInfo_.client = NULL;
      resource_client->DidFail(clientInfo_.id);
    }
}


///
///
///--------------------------------------------------
#if 0
void WebPluginImpl::WillFollowRedirect(
    blink::WebURLLoader* loader,    
    const blink::WebURL& new_url,
    const blink::WebURL& new_site_for_cookies,    
    const blink::WebString& new_referrer,
    network::mojom::ReferrerPolicy new_referrer_policy,
    const blink::WebString& new_method,
    const blink::WebURLResponse& passed_redirect_response,
    bool& report_raw_headers) {
  // TODO(jam): THIS LOGIC IS COPIED IN PluginURLFetcher::OnReceivedRedirect
  // until kDirectNPAPIRequests is the default and we can remove this old path.
  WebPluginImpl::ClientInfo* client_info = GetClientInfoFromLoader(loader);
  if (client_info) {
    // Currently this check is just to catch an https -> http redirect when
    // loading the main plugin src URL. Longer term, we could investigate
    // firing mixed diplay or scripting issues for subresource loads
    // initiated by plugins.
    if (client_info->is_plugin_src_load && webframe_ &&
        !webframe_->checkIfRunInsecureContent(new_url)) {
      std::cout<<"--------------[TODO]---WebPluginImpl::WillFollowRedirect-0--"<<std::endl;
      // loader->Cancel();
      client_info->client->DidFail(client_info->id);
      return;
    }
    if (net::HttpResponseHeaders::IsRedirectResponseCode(
            passed_redirect_response.HttpStatusCode())) {
      // If the plugin does not participate in url redirect notifications then
      // just block cross origin 307 POST redirects.
      if (!client_info->notify_redirects) {
        if (passed_redirect_response.HttpStatusCode() == 307 &&
            base::LowerCaseEqualsASCII(new_method.Utf8(), "post")) {
          GURL original_request_url(passed_redirect_response.ResponseUrl());
          GURL response_url(new_url);
          if (original_request_url.GetOrigin() != response_url.GetOrigin()) {
            loader->SetDefersLoading(true);
            std::cout<<"--------------[TODO]---WebPluginImpl::WillFollowRedirect-1--"<<std::endl;
            // loader->Cancel();
            client_info->client->DidFail(client_info->id);
            return;
          }
        }
      } else {
        loader->SetDefersLoading(true);
      }
    }
    client_info->client->WillSendRequest(new_url, passed_redirect_response.HttpStatusCode());
  }
}

void WebPluginImpl::DidSendData(blink::WebURLLoader* loader,
                                unsigned long long bytes_sent,
                                unsigned long long total_bytes_to_be_sent) {}

void WebPluginImpl::DidReceiveResponse(WebURLLoader* loader,
                                       const WebURLResponse& response) {
  // TODO(jam): THIS LOGIC IS COPIED IN PluginURLFetcher::OnReceivedResponse
  // until kDirectNPAPIRequests is the default and we can remove this old path.
  static const int kHttpPartialResponseStatusCode = 206;
  static const int kHttpResponseSuccessStatusCode = 200;

  WebPluginResourceClient* client = GetClientFromLoader(loader);
  if (!client)
    return;

  ResponseInfo response_info;
  GetResponseInfo(response, &response_info);
  ClientInfo* loader_client_info = GetClientInfoFromLoader(loader);
  if (!loader_client_info)
    return;

  bool request_is_seekable = true;
  if (client->IsMultiByteResponseExpected()) {
    if (response.HttpStatusCode() == kHttpPartialResponseStatusCode) {
      ClientInfo* client_info = GetClientInfoFromLoader(loader);
      if (!client_info)
        return;
      if (HandleHttpMultipartResponse(response, client)) {
        // Multiple ranges requested, data will be delivered by
        // MultipartResponseDelegate.
        client_info->data_offset = 0;
        return;
      }
      int64_t upper_bound = 0, instance_size = 0;
      // Single range requested - go through original processing for
      // non-multipart requests, but update data offset.
      MultipartResponseDelegate::ReadContentRanges(
          response, &client_info->data_offset, &upper_bound, &instance_size);
    } else if (response.HttpStatusCode() == kHttpResponseSuccessStatusCode) {
      RenderThread::Get()->RecordAction(
          base::UserMetricsAction("Plugin_200ForByteRange"));
      // If the client issued a byte range request and the server responds with
      // HTTP 200 OK, it indicates that the server does not support byte range
      // requests.
      // We need to emulate Firefox behavior by doing the following:-
      // 1. Destroy the plugin instance in the plugin process. Ensure that
      //    existing resource requests initiated for the plugin instance
      //    continue to remain valid.
      // 2. Create a new plugin instance and notify it about the response
      //    received here.
      if (!ReinitializePluginForResponse(loader)) {
        NOTREACHED();
        return;
      }

      // The server does not support byte range requests. No point in creating
      // seekable streams.
      request_is_seekable = false;

      delete client;
      client = NULL;

      // Create a new resource client for this request.
      for (size_t i = 0; i < clients_.size(); ++i) {
        if (clients_[i].loader.get() == loader) {
          WebPluginResourceClient* resource_client =
              delegate_->CreateResourceClient(clients_[i].id, plugin_url_, 0);
          clients_[i].client = resource_client;
          client = resource_client;
          break;
        }
      }

      DCHECK(client != NULL);
    }
  }

  // Calling into a plugin could result in reentrancy if the plugin yields
  // control to the OS like entering a modal loop etc. Prevent this by
  // stopping further loading until the plugin notifies us that it is ready to
  // accept data
  loader->SetDefersLoading(true);

  client->DidReceiveResponse(response_info.mime_type, GetAllHeaders(response),
                             response_info.expected_length,
                             response_info.last_modified, request_is_seekable);

  // Bug http://b/issue?id=925559. The flash plugin would not handle the HTTP
  // error codes in the stream header and as a result, was unaware of the
  // fate of the HTTP requests issued via NPN_GetURLNotify. Webkit and FF
  // destroy the stream and invoke the NPP_DestroyStream function on the
  // plugin if the HTTP request fails.
  const GURL& url = response.ResponseUrl();
  if (url.SchemeIs(url::kHttpScheme) || url.SchemeIs(url::kHttpsScheme)) {
    if (response.HttpStatusCode() < 100 || response.HttpStatusCode() >= 400) {
      // The plugin instance could be in the process of deletion here.
      // Verify if the WebPluginResourceClient instance still exists before
      // use.
      ClientInfo* info = GetClientInfoFromLoader(loader);
      if (info) {
        info->pending_failure_notification = true;
      }
    }
  }
}

void WebPluginImpl::DidReceiveData(WebURLLoader* loader,
                                   const char* buffer,
                                   int data_length,
                                   int encoded_data_length) {
  WebPluginResourceClient* client = GetClientFromLoader(loader);
  if (!client)
    return;

  MultiPartResponseHandlerMap::iterator index =
      multi_part_response_map_.find(client);
  if (index != multi_part_response_map_.end()) {
    MultipartResponseDelegate* multi_part_handler = (*index).second;
    DCHECK(multi_part_handler != NULL);
    multi_part_handler->OnReceivedData(buffer, data_length,
                                       encoded_data_length);
  } else {
    loader->SetDefersLoading(true);
    ClientInfo* client_info = GetClientInfoFromLoader(loader);
    client->DidReceiveData(buffer, data_length, client_info->data_offset);
    client_info->data_offset += data_length;
  }
}

void WebPluginImpl::DidFinishLoading(blink::WebURLLoader* loader,
                                     base::TimeTicks finish_time,
                                     int64_t total_encoded_data_length,
                                     int64_t total_encoded_body_length,
                                     int64_t total_decoded_body_length,
                                     bool should_report_corb_blocking) {
  ClientInfo* client_info = GetClientInfoFromLoader(loader);
  if (client_info && client_info->client) {
    MultiPartResponseHandlerMap::iterator index =
        multi_part_response_map_.find(client_info->client);
    if (index != multi_part_response_map_.end()) {
      delete (*index).second;
      multi_part_response_map_.erase(index);
      DidStopLoading();
    }
    loader->SetDefersLoading(true);
    WebPluginResourceClient* resource_client = client_info->client;
    // The ClientInfo can get deleted in the call to DidFinishLoading below.
    // It is not safe to access this structure after that.
    client_info->client = NULL;
    resource_client->DidFinishLoading(client_info->id);
  }
}

void WebPluginImpl::DidFail(WebURLLoader* loader, const WebURLError& error) {
  ClientInfo* client_info = GetClientInfoFromLoader(loader);
  if (client_info && client_info->client) {
    loader->SetDefersLoading(true);
    WebPluginResourceClient* resource_client = client_info->client;
    // The ClientInfo can get deleted in the call to DidFail below.
    // It is not safe to access this structure after that.
    client_info->client = NULL;
    resource_client->DidFail(client_info->id);
  }
}
#endif
///
///
///-----------------------------------------------------------------------------------

void WebPluginImpl::RemoveClient(size_t i) {
  // clients_.erase(clients_.begin() + i);
}

void WebPluginImpl::RemoveClient(WebURLLoader* loader) {
  // for (size_t i = 0; i < clients_.size(); ++i) {
  //   if (clients_[i].loader.get() == loader) {
  //     RemoveClient(i);
  //     return;
  //   }
  // }
}

void WebPluginImpl::SetContainer(WebPluginContainer* container) {
  if (!container)
    TearDownPluginInstance();
  container_ = container;
  if (container_)
    container_->AllowScriptObjects();
}

void WebPluginImpl::HandleURLRequest(const char* url,
                                     const char* method,
                                     const char* target,
                                     const char* buf,
                                     unsigned int len,
                                     int notify_id,
                                     bool popups_allowed,
                                     bool notify_redirects) {
  // GetURL/PostURL requests initiated explicitly by plugins should specify the
  // plugin SRC url as the referrer if it is available.
  HandleURLRequestInternal(url, method, target, buf, len, notify_id,
                           popups_allowed, PLUGIN_SRC, notify_redirects, false);
}

void WebPluginImpl::HandleURLRequestInternal(const char* url,
                                             const char* method,
                                             const char* target,
                                             const char* buf,
                                             unsigned int len,
                                             int notify_id,
                                             bool popups_allowed,
                                             ReferrerValue referrer_flag,
                                             bool notify_redirects,
                                             bool is_plugin_src_load) {
  // For this request, we either route the output to a frame
  // because a target has been specified, or we handle the request
  // here, i.e. by executing the script if it is a javascript url
  // or by initiating a download on the URL, etc. There is one special
  // case in that the request is a javascript url and the target is "_self",
  // in which case we route the output to the plugin rather than routing it
  // to the plugin's frame.
  bool is_javascript_url =
      url::FindAndCompareScheme(url, strlen(url), url::kJavaScriptScheme, NULL);
  RoutingStatus routing_status =
      RouteToFrame(url, is_javascript_url, popups_allowed, method, target, buf,
                   len, notify_id, referrer_flag);
  if (routing_status == ROUTED)
    return;

  if (is_javascript_url) {
    GURL gurl(url);
    WebString result = container_->ExecuteScriptURL(gurl, popups_allowed);

    // delegate_ could be NULL because executeScript caused the container to
    // be deleted.
    if (delegate_) {
      delegate_->SendJavaScriptStream(gurl, result.Utf8(), !result.IsNull(),
                                      notify_id);
    }

    return;
  }

  unsigned long resource_id = GetNextResourceId();
  if (!resource_id)
    return;

  GURL complete_url = CompleteURL(url);
  // Remove when flash bug is fixed. http://crbug.com/40016.
  if (!WebPluginImpl::IsValidUrl(complete_url, referrer_flag))
    return;

  // If the RouteToFrame call returned a failure then inform the result
  // back to the plugin asynchronously.
  if ((routing_status == INVALID_URL) || (routing_status == GENERAL_FAILURE)) {
    WebPluginResourceClient* resource_client =
        delegate_->CreateResourceClient(resource_id, complete_url, notify_id);
    if (resource_client)
      resource_client->DidFail(resource_id);
    return;
  }

  // CreateResourceClient() sends a synchronous IPC message so it's possible
  // that TearDownPluginInstance() may have been called in the nested
  // message loop.  If so, don't start the request.
  if (!delegate_)
    return;

  if (!base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kDisableDirectNPAPIRequests)) {
    // We got here either because the plugin called GetURL/PostURL, or because
    // we're fetching the data for an embed tag. If we're in multi-process mode,
    // we want to fetch the data in the plugin process as the renderer won't be
    // able to request any origin when site isolation is in place. So bounce
    // this request back to the plugin process which will use ResourceDispatcher
    // to fetch the url.

    // TODO(jam): any better way of getting this? Can't find a way to get
    // frame()->loader()->outgoingReferrer() which
    // WebFrameImpl::setReferrerForRequest does.
    WebURLRequest request(complete_url);
    SetReferrer(&request, referrer_flag);
    request.SetReferrerPolicy(network::mojom::ReferrerPolicy::kAlways);
    Referrer referrer(
      #if 0
        GURL(request.HttpHeaderField(WebString::FromUTF8("Referer")).Utf8()),
      #else
        GURL(request.ReferrerString().Utf8()),
      #endif
        request.GetReferrerPolicy());

    GURL first_party_for_cookies =
        webframe_->IsWebLocalFrame()
            ? webframe_->ToWebLocalFrame()->GetDocument().SiteForCookies().RepresentativeUrl()
            : blink::WebDocument().SiteForCookies().RepresentativeUrl();
    delegate_->FetchURL(
        resource_id, notify_id, complete_url, first_party_for_cookies, method,
        buf, len, referrer, notify_redirects, is_plugin_src_load, 0,
        render_frame_->GetRoutingID(), render_view_->GetRoutingID());
  } else {
    WebPluginResourceClient* resource_client =
        delegate_->CreateResourceClient(resource_id, complete_url, notify_id);
    if (!resource_client)
      return;
    InitiateHTTPRequest(resource_id, resource_client, complete_url, method, buf,
                        len, NULL, referrer_flag, notify_redirects,
                        is_plugin_src_load);
  }
}

unsigned long WebPluginImpl::GetNextResourceId() {
  if (!webframe_)
    return 0;
  WebView* view = webframe_->View();
  if (!view)
    return 0;
  return view->CreateUniqueIdentifierForRequest();
}

bool WebPluginImpl::InitiateHTTPRequest(unsigned long resource_id,
                                        WebPluginResourceClient* client,
                                        const GURL& url,
                                        const char* method,
                                        const char* buf,
                                        int buf_len,
                                        const char* range_info,
                                        ReferrerValue referrer_flag,
                                        bool notify_redirects,
                                        bool is_plugin_src_load) {
  if (!client) {
    NOTREACHED();
    return false;
  }

  blink::WebDocument document =
      webframe_->IsWebLocalFrame() ? webframe_->ToWebLocalFrame()->GetDocument()
                                   : blink::WebDocument();
  //--------[FIX] FIX BY HWB
  // ClientInfo info;
  clientInfo_.id = resource_id;
  clientInfo_.client = client;
  clientInfo_.request.SetUrl(url);
  clientInfo_.request.SetSiteForCookies(document.SiteForCookies());
  clientInfo_.request.SetRequestorID(delegate_->GetProcessId());
  // TODO(mkwst): Is this a request for a plugin object itself
  // (RequestContextObject), or a request that the plugin makes
  // (RequestContextPlugin)?
  clientInfo_.request.SetRequestContext(blink::mojom::RequestContextType::PLUGIN);
  clientInfo_.request.SetHttpMethod(WebString::FromUTF8(method));
  // ServiceWorker is disabled for NPAPI.
  clientInfo_.request.SetSkipServiceWorker(true);
  clientInfo_.pending_failure_notification = false;
  clientInfo_.notify_redirects = notify_redirects;
  clientInfo_.is_plugin_src_load = is_plugin_src_load;
  clientInfo_.data_offset = 0;

  if (range_info) {
    clientInfo_.request.AddHttpHeaderField(WebString::FromUTF8("Range"),
                                    WebString::FromUTF8(range_info));
  }

  if (strcmp(method, "POST") == 0) {
    // Adds headers or form data to a request.  This must be called before
    // we initiate the actual request.
    SetPostData(&clientInfo_.request, buf, buf_len);
  }

  SetReferrer(&clientInfo_.request, referrer_flag);

  if (!webframe_->IsWebLocalFrame())
    return false;

  WebLocalFrame* frame = webframe_->ToWebLocalFrame();
  if (!frame)
    return false;

  blink::WebAssociatedURLLoaderOptions options;
  options.grant_universal_access = true;
  options.preflight_policy =
      network::mojom::CorsPreflightPolicy::kConsiderPreflight;;
  std::cout<<"-------------[TODO]-------WebPluginImpl::InitiateHTTPRequest"<<std::endl;      
  clientInfo_.loader.reset(frame->CreateAssociatedURLLoader(options));
  if (!clientInfo_.loader.get())
    return false;
  clientInfo_.loader->LoadAsynchronously(clientInfo_.request, &loader_client_);

  // clients_.push_back(info);
  return true;
}

void WebPluginImpl::CancelDocumentLoad() {
  if (webframe_) {
    ignore_response_error_ = true;
    webframe_->StopLoading();
  }
}

void WebPluginImpl::InitiateHTTPRangeRequest(const char* url,
                                             const char* range_info,
                                             int range_request_id) {
  unsigned long resource_id = GetNextResourceId();
  if (!resource_id)
    return;

  GURL complete_url = CompleteURL(url);
  // Remove when flash bug is fixed. http://crbug.com/40016.
  if (!WebPluginImpl::IsValidUrl(complete_url,
                                 load_manually_ ? NO_REFERRER : PLUGIN_SRC))
    return;

  WebPluginResourceClient* resource_client =
      delegate_->CreateSeekableResourceClient(resource_id, range_request_id);
  InitiateHTTPRequest(resource_id, resource_client, complete_url, "GET", NULL,
                      0, range_info, load_manually_ ? NO_REFERRER : PLUGIN_SRC,
                      false, false);
}

void WebPluginImpl::DidStartLoading() {
  // if (render_view_.get()) {
  //   // TODO(darin): Make is_loading_ be a counter!
  //   render_view_->DidStartLoading();
  // }

  if(render_frame_){
    render_frame_->DidStartLoading();
  }
}

void WebPluginImpl::DidStopLoading() {
  // if (render_view_.get()) {
  //   // TODO(darin): Make is_loading_ be a counter!
  //   render_view_->DidStopLoading();
  // }

    if (render_frame_) {
    // TODO(darin): Make is_loading_ be a counter!
    render_frame_->DidStopLoading();
  }
}

void WebPluginImpl::SetDeferResourceLoading(unsigned long resource_id,
                                            bool defer) {
  ///---------[FIX] FIX BY HWB
  // std::vector<ClientInfo>::iterator client_index = clients_.begin();
  // while (client_index != clients_.end()) {
  //   ClientInfo& client_info = *client_index;

    if (clientInfo_.id == resource_id) {
      clientInfo_.loader->SetDefersLoading(defer);

      // If we determined that the request had failed via the HTTP headers
      // in the response then we send out a failure notification to the
      // plugin process, as certain plugins don't handle HTTP failure codes
      // correctly.
      if (!defer && clientInfo_.client &&
          clientInfo_.pending_failure_notification) {
        // The ClientInfo and the iterator can become invalid due to the call
        // to DidFail below.
        WebPluginResourceClient* resource_client = clientInfo_.client;        
        clientInfo_.loader->Cancel();
        // clients_.erase(client_index++);
        resource_client->DidFail(resource_id);
      }
      // break;
    }
  //   client_index++;
  // }
}

bool WebPluginImpl::IsOffTheRecord() {
  return false;
}

bool WebPluginImpl::HandleHttpMultipartResponse(
    const WebURLResponse& response,
    WebPluginResourceClient* client) {
  std::string multipart_boundary;
  if (!MultipartResponseDelegate::ReadMultipartBoundary(response,
                                                        &multipart_boundary)) {
    return false;
  }

  DidStartLoading();

  MultiPartResponseClient* multi_part_response_client =
      new MultiPartResponseClient(client);

  MultipartResponseDelegate* multi_part_response_handler =
      new MultipartResponseDelegate(multi_part_response_client, NULL, response,
                                    multipart_boundary);
  multi_part_response_map_[client] = multi_part_response_handler;
  return true;
}

// bool WebPluginImpl::ReinitializePluginForResponse(WebURLLoader* loader) {
bool WebPluginImpl::ReinitializePluginForResponse() {  
  WebFrame* webframe = webframe_;
  if (!webframe)
    return false;

  WebView* webview = webframe->View();
  if (!webview)
    return false;

  WebPluginContainer* container_widget = container_;

  // Destroy the current plugin instance.
  TearDownPluginInstance();

  container_ = container_widget;
  webframe_ = webframe;

  WebPluginDelegateProxy* plugin_delegate =
      new WebPluginDelegateProxy(this, mime_type_, render_view_, render_frame_);

  // Store the plugin's unique identifier, used by the container to track its
  // script objects, and enable script objects (since Initialize may use them
  // even if it fails).
  npp_ = plugin_delegate->GetPluginNPP();
  container_->AllowScriptObjects();

  bool ok = plugin_delegate &&
            plugin_delegate->Initialize(plugin_url_, arg_names_, arg_values_,
                                        load_manually_);

  if (!ok) {
    container_->ClearScriptObjects();
    container_ = NULL;
    // TODO(iyengar) Should we delete the current plugin instance here?
    return false;
  }

  delegate_ = plugin_delegate;

  // Force a geometry update to occur to ensure that the plugin becomes
  // visible.
  container_->ReportGeometry();

  // The plugin move sequences accumulated via DidMove are sent to the browser
  // whenever the renderer paints. Force a paint here to ensure that changes
  // to the plugin window are propagated to the browser.
  container_->Invalidate();
  return true;
}

// void WebPluginImpl::TearDownPluginInstance(WebURLLoader* loader_to_ignore) {
void WebPluginImpl::TearDownPluginInstance() {
  // JavaScript garbage collection may cause plugin script object references to
  // be retained long after the plugin is destroyed. Some plugins won't cope
  // with their objects being released after they've been destroyed, and once
  // we've actually unloaded the plugin the object's releaseobject() code may
  // no longer be in memory. The container tracks the plugin's objects and lets
  // us invalidate them, releasing the references to them held by the JavaScript
  // runtime.
  if (container_) {
    container_->ClearScriptObjects();
    container_->SetCcLayer(nullptr, false);
  }

  // Call PluginDestroyed() first to prevent the plugin from calling us back
  // in the middle of tearing down the render tree.
  if (delegate_) {
    // The plugin may call into the browser and pass script objects even during
    // teardown, so temporarily re-enable plugin script objects.
    DCHECK(container_);
    container_->AllowScriptObjects();

    delegate_->PluginDestroyed();
    delegate_ = NULL;

    // Invalidate any script objects created during teardown here, before the
    // plugin might actually be unloaded.
    container_->ClearScriptObjects();
  }

  if (clientInfo_.loader.get())
      clientInfo_.loader->Cancel();

  // Cancel any pending requests because otherwise this deleted object will
  // be called by the ResourceDispatcher.
  //---------[FIX] FIX BY HWB
  // std::vector<ClientInfo>::iterator client_index = clients_.begin();
  // while (client_index != clients_.end()) {
  //   ClientInfo& client_info = *client_index;

  //   if (loader_to_ignore == client_info.loader) {
  //     client_index++;
  //     continue;
  //   }

  //   std::cout<<"---------------[TODO]---WebPluginImpl::TearDownPluginInstance---"<<std::endl;
  //   // if (client_info.loader.get())
  //   //   client_info.loader->Cancel();

  //   client_index = clients_.erase(client_index);
  // }

  // This needs to be called now and not in the destructor since the
  // webframe_ might not be valid anymore.
  webframe_ = NULL;
  weak_factory_.InvalidateWeakPtrs();
}

void WebPluginImpl::SetReferrer(blink::WebURLRequest* request,
                                ReferrerValue referrer_flag) {
  if (!webframe_ || !webframe_->IsWebLocalFrame())
    return;

  WebLocalFrame* frame = webframe_->ToWebLocalFrame();
  if (!frame)
    return;

  switch (referrer_flag) {
    case DOCUMENT_URL:
      frame->SetReferrerForRequest(*request, GURL());
      break;

    case PLUGIN_SRC:
      frame->SetReferrerForRequest(*request, plugin_url_);
      break;

    default:
      break;
  }
}

}  // namespace content
