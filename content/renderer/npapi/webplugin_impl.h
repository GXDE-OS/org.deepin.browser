// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_RENDERER_NPAPI_WEBPLUGIN_IMPL_
#define CONTENT_RENDERER_NPAPI_WEBPLUGIN_IMPL_

#include <map>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/memory/weak_ptr.h"
#include "content/child/npapi/webplugin.h"
#include "content/common/content_export.h"
#include "content/common/webplugin_geometry.h"
#include "third_party/blink/public/platform/web_rect.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_loader_client.h"
#include "third_party/blink/public/web/web_associated_url_loader_client.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_widget.h"
#include "ui/gfx/native_widget_types.h"
#include "services/network/public/mojom/referrer_policy.mojom.h"
#include "url/gurl.h"
#include "base/memory/linked_ptr.h"  
#include "third_party/blink/public/web/web_associated_url_loader.h"
#include "content/child/npapi/webplugin_resource_client.h"
namespace cc {
class IOSurfaceLayer;
}

namespace blink {
class WebFrame;
class WebLayer;
class WebPluginContainer;
class WebURLResponse;
class WebURLLoader;
class WebURLRequest;
class WebCoalescedInputEvent;
class WebWidget;
struct WebPluginParams;
}

namespace content {
class MultipartResponseDelegate;
class RenderFrameImpl;
class RenderViewImpl;
class WebPluginDelegateProxy;


// This is the WebKit side of the plugin implementation that forwards calls,
// after changing out of WebCore types, to a delegate.  The delegate may
// be in a different process.
class WebPluginImpl : public WebPlugin,
                      public blink::WebPlugin {
 public:
  WebPluginImpl(
      blink::WebFrame* frame,
      const blink::WebPluginParams& params,
      const base::FilePath& file_path,
      const base::WeakPtr<RenderViewImpl>& render_view,
      RenderFrameImpl* render_frame);
  ~WebPluginImpl() override;
  typedef struct ClientInfo {
      unsigned long id;
      WebPluginResourceClient* client;
      blink::WebURLRequest request;
      bool pending_failure_notification;
      // linked_ptr<blink::WebURLLoader> loader;
      linked_ptr<blink::WebAssociatedURLLoader> loader;
      bool notify_redirects;
      bool is_plugin_src_load;
      int64_t data_offset;
  } ClientInfo;
  // Helper function for sorting post data.
  CONTENT_EXPORT static bool SetPostData(blink::WebURLRequest* request,
                                         const char* buf,
                                         uint32_t length);

  blink::WebFrame* webframe() { return webframe_; }

  // blink::WebPlugin methods:
  bool Initialize(blink::WebPluginContainer* container) override;
  void Destroy() override;
  NPObject* ScriptableObject() override;  
  struct _NPP* PluginNPP() override;  
  bool GetFormValue(blink::WebString& value) override;
  // void LayoutIfNeeded() override;
  void Paint(cc::PaintCanvas* canvas,
             const blink::WebRect& paint_rect) override;
  void UpdateGeometry(const blink::WebRect& window_rect,
                      const blink::WebRect& clip_rect,
                      const blink::WebRect& unobscured_rect,        
                      bool is_visible) override;
  void UpdateFocus(bool focused, blink::mojom::FocusType focus_type) override;
  void UpdateVisibility(bool visible) override;
  bool AcceptsInputEvents();
  blink::WebInputEventResult HandleInputEvent(
      const blink::WebCoalescedInputEvent& event,
      ui::Cursor* cursor_info) override;
  void DidReceiveResponse(const blink::WebURLResponse& response) override;
  // virtual void DidReceiveData(const char* data, size_t data_length) = 0;
  void DidReceiveData(const char* data, size_t data_length) override;
  void DidFinishLoading() override;
  void DidFailLoading(const blink::WebURLError& error) override;
  void DidFinishLoadingFrameRequest(const blink::WebURL& url,
                                    void* notify_data) override;
  void DidFailLoadingFrameRequest(const blink::WebURL& url,
                                  void* notify_data,
                                  const blink::WebURLError& error) override;
  bool IsPlaceholder() ;
  bool IsNPPlugin() ;
  void UpdateAllLifecyclePhases(blink::DocumentUpdateReason reason) override{}
  // void UpdateAllLifecyclePhases() override {}

  // WebPlugin implementation:
  void SetWindow(gfx::PluginWindowHandle window) override;
  void SetAcceptsInputEvents(bool accepts) override;
  void WillDestroyWindow(gfx::PluginWindowHandle window) override;
  void CancelResource(unsigned long id) override;
  void Invalidate() override;
  void InvalidateRect(const gfx::Rect& rect) override;
  NPObject* GetWindowScriptNPObject() override;
  NPObject* GetPluginElement() override;
  bool FindProxyForUrl(const GURL& url, std::string* proxy_list) override;
  void SetCookie(const GURL& url,
                 const GURL& first_party_for_cookies,
                 const std::string& cookie) override;
  std::string GetCookies(const GURL& url,
                         const GURL& first_party_for_cookies) override;
  void HandleURLRequest(const char* url,
                        const char* method,
                        const char* target,
                        const char* buf,
                        unsigned int len,
                        int notify_id,
                        bool popups_allowed,
                        bool notify_redirects) override;
  void CancelDocumentLoad() override;
  void InitiateHTTPRangeRequest(const char* url,
                                const char* range_info,
                                int pending_request_id) override;
  void DidStartLoading() override;
  void DidStopLoading() override;
  bool IsOffTheRecord() override;
  void SetDeferResourceLoading(unsigned long resource_id, bool defer) override;
  void URLRedirectResponse(bool allow, int resource_id) override;
  bool CheckIfRunInsecureContent(const GURL& url) override;
  

#if defined(OS_WIN)
  void SetWindowlessData(HANDLE pump_messages_event,
                         gfx::NativeViewId dummy_activation_window) override {}
  void ReparentPluginWindow(HWND window, HWND parent) { }
  void ReportExecutableMemory(size_t size) { }
#endif
#if defined(OS_MACOSX)
  WebPluginAcceleratedSurface* GetAcceleratedSurface(
      gfx::GpuPreference gpu_preference) override;
  void AcceleratedPluginEnabledRendering() override;
  void AcceleratedPluginAllocatedIOSurface(int32 width,
                                           int32 height,
                                           uint32 surface_id) override;
  void AcceleratedPluginSwappedIOSurface() override;
#endif

 private:
  // Given a (maybe partial) url, completes using the base url.
  GURL CompleteURL(const char* url);

  enum RoutingStatus {
    ROUTED,
    NOT_ROUTED,
    INVALID_URL,
    GENERAL_FAILURE
  };

  // Determines the referrer value sent along with outgoing HTTP requests
  // issued by plugins.
  enum ReferrerValue {
    PLUGIN_SRC,
    DOCUMENT_URL,
    NO_REFERRER
  };

  // Given a download request, check if we need to route the output to a frame.
  // Returns ROUTED if the load is done and routed to a frame, NOT_ROUTED or
  // corresponding error codes otherwise.
  RoutingStatus RouteToFrame(const char* url,
                             bool is_javascript_url,
                             bool popups_allowed,
                             const char* method,
                             const char* target,
                             const char* buf,
                             unsigned int len,
                             int notify_id,
                             ReferrerValue referrer_flag);

  // Returns the next avaiable resource id. Returns 0 if the operation fails.
  // It may fail if the page has already been closed.
  unsigned long GetNextResourceId();

  // Initiates HTTP GET/POST requests.
  // Returns true on success.
  bool InitiateHTTPRequest(unsigned long resource_id,
                           WebPluginResourceClient* client,
                           const GURL& url,
                           const char* method,
                           const char* buf,
                           int len,
                           const char* range_info,
                           ReferrerValue referrer_flag,
                           bool notify_redirects,
                           bool check_mixed_scripting);

  gfx::Rect GetWindowClipRect(const gfx::Rect& rect);

  // Sets the actual Widget for the plugin.
  void SetContainer(blink::WebPluginContainer* container);

  // Destroys the plugin instance.
  // The response_handle_to_ignore parameter if not NULL indicates the
  // resource handle to be left valid during plugin shutdown.
  // void TearDownPluginInstance(blink::WebURLLoader* loader_to_ignore);
  void TearDownPluginInstance();

  // WebURLLoaderClient implementation.  We implement this interface in the
  // renderer process, and then use the simple WebPluginResourceClient interface
  // to relay the callbacks to the plugin.
  ///remove by hwb for interface change to associate url
  // void WillFollowRedirect(blink::WebURLLoader*,
  //                         const blink::WebURL& new_url,
  //                         const blink::WebURL& new_site_for_cookies,
  //                         const blink::WebString& new_referrer,
  //                         network::mojom::ReferrerPolicy new_referrer_policy,
  //                         const blink::WebString& new_method,
  //                         const blink::WebURLResponse& passed_redirect_response,
  //                         bool& report_raw_headers);
                         
  // void DidSendData(blink::WebURLLoader* loader,
  //                  unsigned long long bytes_sent,
  //                  unsigned long long total_bytes_to_be_sent);
  // void DidReceiveResponse(blink::WebURLLoader* loader,
  //                         const blink::WebURLResponse& response);

  // void DidReceiveData(blink::WebURLLoader* loader, const char *buffer,
  //                     int data_length, int encoded_data_length);
  // void DidFinishLoading(blink::WebURLLoader* loader,
  //                       base::TimeTicks finish_time,
  //                       int64_t total_encoded_data_length,
  //                       int64_t total_encoded_body_length,
  //                       int64_t total_decoded_body_length,
  //                       bool should_report_corb_blocking);
  // void DidFail(blink::WebURLLoader* loader,
  //              const blink::WebURLError& error);


  void WillFollowRedirect(const blink::WebURL& new_url,
                                  const blink::WebURLResponse& redirect_response);  
  void SendData(uint64_t, uint64_t);
  void ReceiveResponse(const blink::WebURLResponse&);
  // void DidDownloadData(uint64_t data_length);
  void ReceiveData(const char* data, int data_length);
  // void DidReceiveCachedMetadata(const char* data, int data_length);
  void FinishLoading();
  void Fail(const blink::WebURLError&);                

  // Helper function to remove the stored information about a resource
  // request given its index in m_clients.
  void RemoveClient(size_t i);

  // Helper function to remove the stored information about a resource
  // request given a handle.
  void RemoveClient(blink::WebURLLoader* loader);

  // Handles HTTP multipart responses, i.e. responses received with a HTTP
  // status code of 206.
  // Returns false if response is not multipart (may be if we requested
  // single range).
  bool HandleHttpMultipartResponse(const blink::WebURLResponse& response,
                                   WebPluginResourceClient* client);

  void HandleURLRequestInternal(const char* url,
                                const char* method,
                                const char* target,
                                const char* buf,
                                unsigned int len,
                                int notify_id,
                                bool popups_allowed,
                                ReferrerValue referrer_flag,
                                bool notify_redirects,
                                bool check_mixed_scripting);

  // Tears down the existing plugin instance and creates a new plugin instance
  // to handle the response identified by the loader parameter.
  // bool ReinitializePluginForResponse(blink::WebURLLoader* loader);
  bool ReinitializePluginForResponse();

  // Delayed task for downloading the plugin source URL.
  void OnDownloadPluginSrcUrl();


  // Helper functions
  WebPluginResourceClient* GetClientFromLoader(blink::WebURLLoader* loader);
  ClientInfo* GetClientInfoFromLoader(blink::WebURLLoader* loader);

  // Helper function to set the referrer on the request passed in.
  void SetReferrer(blink::WebURLRequest* request, ReferrerValue referrer_flag);

  // Check for invalid chars like @, ;, \ before the first / (in path).
  bool IsValidUrl(const GURL& url, ReferrerValue referrer_flag);

  // std::vector<ClientInfo> clients_;
  ClientInfo clientInfo_;

  bool windowless_;
  gfx::PluginWindowHandle window_;
#if defined(OS_MACOSX)
  bool next_io_surface_allocated_;
  int32 next_io_surface_width_;
  int32 next_io_surface_height_;
  uint32 next_io_surface_id_;
  scoped_refptr<cc::IOSurfaceLayer> io_surface_layer_;
  scoped_ptr<blink::WebLayer> web_layer_;
#endif
  bool accepts_input_events_;
  RenderFrameImpl* render_frame_;
  base::WeakPtr<RenderViewImpl> render_view_;
  blink::WebFrame* webframe_;

  WebPluginDelegateProxy* delegate_;

  // This is just a weak reference.
  blink::WebPluginContainer* container_;

  // Unique identifier for this plugin, used to track script objects.
  struct _NPP* npp_;

  typedef std::map<WebPluginResourceClient*, MultipartResponseDelegate*>
      MultiPartResponseHandlerMap;
  // Tracks HTTP multipart response handlers instantiated for
  // a WebPluginResourceClient instance.
  MultiPartResponseHandlerMap multi_part_response_map_;

  // The plugin source URL.
  GURL plugin_url_;

  // Indicates if the download would be initiated by the plugin or us.
  bool load_manually_;

  // Indicates if this is the first geometry update received by the plugin.
  bool first_geometry_update_;

  // Set to true if the next response error should be ignored.
  bool ignore_response_error_;

  // The current plugin geometry and clip rectangle.
  WebPluginGeometry geometry_;

  // The location of the plugin on disk.
  base::FilePath file_path_;

  // The mime type of the plugin.
  std::string mime_type_;

  // Holds the list of argument names and values passed to the plugin.  We keep
  // these so that we can re-initialize the plugin if we need to.
  std::vector<std::string> arg_names_;
  std::vector<std::string> arg_values_;
#if 0
  class LoaderClient : public blink::WebURLLoaderClient {
   public:
    LoaderClient(WebPluginImpl*);

    bool WillFollowRedirect(
                            // blink::WebURLLoader*,
                            const blink::WebURL& new_url,
                            const blink::WebURL& new_site_for_cookies,
                            const base::Optional<blink::WebSecurityOrigin>& new_top_frame_origin,
                            const blink::WebString& new_referrer,
                            network::mojom::ReferrerPolicy new_referrer_policy,
                            const blink::WebString& new_method,
                            const blink::WebURLResponse& passed_redirect_response,
                            bool& report_raw_headers) override;
    void DidSendData(blink::WebURLLoader*,
                     uint64_t bytes_sent,
                     uint64_t total_bytes_to_be_sent) override;
    void DidReceiveResponse(blink::WebURLLoader*,
                            const blink::WebURLResponse&) override;
    // void DidDownloadData(blink::WebURLLoader*,
    //                      int data_length,
    //                      int encoded_data_length) override;
    void DidReceiveData(blink::WebURLLoader*,
                        const char* data,
                        int data_length) override;
    void DidReceiveCachedMetadata(blink::WebURLLoader*,
                                  const char* data,
                                  int data_length) override;
                               
    void DidFinishLoading(blink::WebURLLoader*,
                          base::TimeTicks finish_time,
                          int64_t total_encoded_data_length,
                          int64_t total_encoded_body_length,
                          int64_t total_decoded_body_length,
                          bool should_report_corb_blocking,
                          const blink::WebVector<network::cors::PreflightTimingInfo>&) override;
    void DidFail(blink::WebURLLoader*,
                 const blink::WebURLError&,
                 int64_t total_encoded_data_length,
                 int64_t total_encoded_body_length,
                 int64_t total_decoded_body_length) override;

   private:
    WebPluginImpl* parent_;
  };
#endif 

  class UosLoaderClient : public blink::WebAssociatedURLLoaderClient {
   public:
    UosLoaderClient(WebPluginImpl*);

  bool WillFollowRedirect(const blink::WebURL& new_url,
                                  const blink::WebURLResponse& redirect_response) override;
  
  void DidSendData(uint64_t bytes_sent,
                           uint64_t total_bytes_to_be_sent) override;
  void DidReceiveResponse(const blink::WebURLResponse&) override;  
  void DidReceiveData(const char* data, int data_length) override;
  void DidReceiveCachedMetadata(const char* data, int data_length) override;
  void DidFinishLoading() override;
  void DidFail(const blink::WebURLError&) override;

   private:
    WebPluginImpl* parent_;
  };

  UosLoaderClient loader_client_;

  base::WeakPtrFactory<WebPluginImpl> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(WebPluginImpl);
};

}  // namespace content

#endif  // CONTENT_RENDERER_NPAPI_WEBPLUGIN_IMPL_
