// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/npapi/plugin_resource_fetcher.h"

#include "content/child/child_thread_impl.h"



#include "base/feature_list.h"
#include "content/child/child_thread_impl.h"
#include "content/renderer/render_thread_impl.h"
#include "content/public/common/service_manager_connection.h"
#include "content/public/common/service_names.mojom.h"

#include "content/renderer/render_frame_impl.h"

#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/service_manager/public/cpp/connector.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/service_manager/public/mojom/connector.mojom.h"
#include "services/network/public/cpp/features.h"

#include "mojo/public/cpp/bindings/interface_request.h"

#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "content/public/common/resource_type.h"


namespace {

const int kMaximumDownloadSize = 10 * 1024 * 1024;

constexpr int32_t kRoutingId = 0;
const char kAccessControlAllowOriginHeader[] = "Access-Control-Allow-Origin";

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

}

namespace content {

// TODO(toyoshim): Internal implementation might be replaced with
// SimpleURLLoader, and content::ResourceFetcher could be a thin-wrapper
// class to use SimpleURLLoader with blink-friendly types.
class PluginResourceFetcher::ClientImpl : public network::mojom::URLLoaderClient {
 public:
  ClientImpl(PluginResourceFetcher* parent,
             size_t maximum_download_size,
             scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : parent_(parent),
        client_binding_(this),
        data_pipe_watcher_(FROM_HERE,
                           mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                           std::move(task_runner)),
        status_(Status::kNotStarted),
        completed_(false),
        maximum_download_size_(maximum_download_size) {
          response_code_ = -1;
        }

  ~ClientImpl() override {
    if (status_ != Status::kClosed) {
      Cancel();
	}
  }

  void Start(int request_id, const network::ResourceRequest& request,
             network::mojom::URLLoaderFactoryAssociatedPtr url_loader_factory,
             // scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
             const net::NetworkTrafficAnnotationTag& annotation_tag,
             scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    status_ = Status::kStarted;
    response_.SetCurrentRequestUrl(request.url);

    network::mojom::URLLoaderClientPtrInfo client;
    client_binding_.Bind(mojo::MakeRequest(&client), std::move(task_runner));

    url_loader_factory->CreateLoaderAndStart(
        mojo::MakeRequest(&loader_), kRoutingId,
        request_id, network::mojom::kURLLoadOptionNone,
        request, std::move(client),
        net::MutableNetworkTrafficAnnotationTag(annotation_tag));
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
    loader_.reset();

    parent_->OnLoadComplete();

    // if (callback_.is_null())
    //   return;

    // std::move(callback_).Run(response_, data_);
    Resource resource;
    resource.mime = mime_;
    resource.head = head_;
    resource.data = data_;
    resource.response_code = response_code_;
    parent_->OnFetchResourceComplete(resource);
  }

  void ClearReceivedDataToFail() {
    response_ = blink::WebURLResponse();
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
    if (response_head->headers) {      
      response_.SetHttpStatusCode(response_head->headers->response_code());

      head_ = response_head->headers->raw_headers();
      std::string m;
      if (response_head->headers->GetMimeType(&m)) {
         mime_ = m;
      }

      response_code_ = response_head->headers->response_code();
    }

  }
  void OnReceiveRedirect(
      const net::RedirectInfo& redirect_info,
      network::mojom::URLResponseHeadPtr response_head) override {
    DCHECK_EQ(Status::kStarted, status_);
    // loader_->FollowRedirect(base::nullopt, response_head->headers, base::nullopt);    
    response_.SetCurrentRequestUrl(redirect_info.new_url);
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
    // data_pipe_watcher_.Watch(
    //     data_pipe_.get(),
    //     MOJO_HANDLE_SIGNAL_READABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
    //     MOJO_WATCH_CONDITION_SATISFIED,
    //     base::BindRepeating(
    //         &PluginResourceFetcher::ClientImpl::OnDataPipeSignaled,
    //         base::Unretained(this)));
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
  PluginResourceFetcher* parent_;
  network::mojom::URLLoaderPtr loader_;
  mojo::Binding<network::mojom::URLLoaderClient> client_binding_;
  mojo::ScopedDataPipeConsumerHandle data_pipe_;
  mojo::SimpleWatcher data_pipe_watcher_;

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

  // int file_scheme_data_length_;

  // Response to be passed to the |callback_|.
  blink::WebURLResponse response_;

  // Callback when we're done.
  // Callback callback_;

  DISALLOW_COPY_AND_ASSIGN(ClientImpl);
};


PluginResourceFetcher::Resource::Resource() {
  request_id = 0;
  resource_id = 0;
  response_code = 0;
}
	
PluginResourceFetcher::PluginResourceFetcher(const GURL& url, Delegate* delegate) 
: delegate_(delegate) {

  url_ = url;

  request_.url = url;

  request_id_ = 0;
  resource_id_ = 0;

  RenderThreadImpl* render_thread = RenderThreadImpl::current();
  DCHECK(render_thread);

  if (base::FeatureList::IsEnabled(network::features::kNetworkService)) {
    // service_manager::mojom::ConnectorRequest request;
    // connector_ = service_manager::Connector::Create(&request);
    // network::mojom::URLLoaderFactoryPtr factory_ptr;
    // connector_->BindInterface(mojom::kBrowserServiceName, &url_loader_factory_);
    // url_loader_factory_ = std::move(factory_ptr);
  } else {
    network::mojom::URLLoaderFactoryAssociatedPtr factory_ptr;
    IPC::SyncChannel* c = render_thread->channel();
    c->GetRemoteAssociatedInterface(&factory_ptr);
    url_loader_factory_ = std::move(factory_ptr);
  }
}

PluginResourceFetcher::~PluginResourceFetcher() {
	  client_.reset();
}

void PluginResourceFetcher::StartAsync(int request_id, int resource_id, RenderFrameImpl* render_frame) {
  DCHECK(!client_);
  DCHECK(render_frame);
  DCHECK(url_loader_factory_);

  if (url_loader_factory_.get() == nullptr)
    return;

  blink::WebLocalFrame* frame = render_frame->GetWebFrame();
  DCHECK(frame);

  request_id_ = request_id;
  resource_id_ = resource_id;

  // DCHECK(!frame->GetDocument().IsNull());
  if (request_.method.empty())
    request_.method = net::HttpRequestHeaders::kGetMethod;
  if (request_.request_body) {
    DCHECK(!base::LowerCaseEqualsASCII(request_.method,
                                       net::HttpRequestHeaders::kGetMethod))
        << "GETs can't have bodies.";
  }

  request_.fetch_request_context_type = static_cast<int>(blink::mojom::RequestContextType::WORKER);

  // request_.site_for_cookies = frame->GetDocument().SiteForCookies();
  if (!frame->GetDocument().GetSecurityOrigin().IsNull()) {
    request_.request_initiator =
        static_cast<url::Origin>(frame->GetDocument().GetSecurityOrigin());
    SetHeader(kAccessControlAllowOriginHeader,
              blink::WebSecurityOrigin::CreateUniqueOpaque().ToString().Ascii());
  }
  // request_.resource_type = WebURLRequestContextToResourceType(request_context);
  request_.resource_type = (int)ResourceType::kObject;

  client_ = std::make_unique<ClientImpl>(
      this, kMaximumDownloadSize, // , std::move(callback)
      frame->GetTaskRunner(blink::TaskType::kNetworking));

  // TODO(kinuko, toyoshim): This task runner should be given by the consumer
  // of this class.
  client_->Start(request_id, request_,
          std::move(url_loader_factory_), 
    net::NetworkTrafficAnnotationTag(kNavigationUrlLoaderTrafficAnnotation),
                 frame->GetTaskRunner(blink::TaskType::kNetworking));

  // No need to hold on to the request; reset it now.
  request_ = network::ResourceRequest();
}

void PluginResourceFetcher::OnClientConnectionError(uint32_t e, const std::string& reason) {
  // TODO(reillyg): Temporary workaround for crbug.com/756751 where without
  // browser-side navigation this error on async loads will confuse the loading
  // of cross-origin iframes.
  // if (is_synchronous_ || content::IsBrowserSideNavigationEnabled())
  //    CancelWithError(net::ERR_ABORTED, nullptr);
  
  // client_binding_.Unbind();
  // delegate_->OnComplete(request_id_, resource_id_, std::string(), std::string(), std::string());
  return;
}


void PluginResourceFetcher::SetMethod(const std::string& method) {
  DCHECK(!client_);
  request_.method = method;
}

void PluginResourceFetcher::SetBody(const std::string& body) {
  DCHECK(!client_);
  request_.request_body =
      network::ResourceRequestBody::CreateFromBytes(body.data(), body.size());
}

void PluginResourceFetcher::SetHeader(const std::string& header,
                                    const std::string& value) {
  DCHECK(!client_);
  if (base::LowerCaseEqualsASCII(header, net::HttpRequestHeaders::kReferer)) {
    request_.referrer = GURL(value);
    DCHECK(request_.referrer.is_valid());
    request_.referrer_policy = Referrer::GetDefaultReferrerPolicy();
  } else {
    request_.headers.SetHeader(header, value);
  }
}

void PluginResourceFetcher::SetSiteCookies(const GURL& cookies) {
  DCHECK(!client_);
  request_.site_for_cookies = net::SiteForCookies::FromUrl(cookies);
}

void PluginResourceFetcher::SetTimeout(const base::TimeDelta& timeout) {
  DCHECK(client_);
  DCHECK(client_->IsActive());
  DCHECK(!timeout_timer_.IsRunning());

  timeout_timer_.Start(FROM_HERE, timeout, this,
                       &PluginResourceFetcher::OnTimeout);
}

void PluginResourceFetcher::OnFetchResourceComplete(Resource& resource) {
  if (request_id_ > 0) {

	// Fix file scheme response code bug
	if (-1 == resource.response_code) {
      if (resource.data.size() > 0) {
        if (url_.SchemeIs("file")) {
          resource.response_code = 10001;
		}
	  }
	}
  
    resource.request_id = request_id_;
    resource.resource_id = resource_id_;

	request_id_ = 0;

	resource_ = resource;

	delay_task_.Start(
            FROM_HERE, base::TimeDelta::FromMilliseconds(50), this,
            &PluginResourceFetcher::OnReleaseResource);
  }
}

void PluginResourceFetcher::OnLoadComplete() {
  timeout_timer_.Stop();
}

void PluginResourceFetcher::OnTimeout() {
  DCHECK(client_);
  DCHECK(client_->IsActive());
  client_->Cancel();
}

void PluginResourceFetcher::OnReleaseResource() {
  delegate_->OnFetchResourceComplete(resource_);
}

}  // namespace content
