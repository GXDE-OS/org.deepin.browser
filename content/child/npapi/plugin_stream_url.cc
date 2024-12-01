// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/child/npapi/plugin_stream_url.h"

#include <algorithm>

#include "base/lazy_instance.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "content/child/npapi/plugin_host.h"
#include "content/child/npapi/plugin_instance.h"
#include "content/child/npapi/plugin_lib.h"
#include "content/child/npapi/plugin_url_fetcher.h"
#include "content/child/npapi/webplugin.h"
#include "content/child/child_thread_impl.h"
#include "content/child/npapi/webplugin_resource_client.h"
#include "content/child/plugin_messages.h"
#include "content/child/request_info.h"
#include "content/common/plugin_process_messages.h"
#include "content/plugin/plugin_thread.h"
#include "content/renderer/loader/request_extra_data.h"
#include "content/renderer/loader/resource_dispatcher.h"
#include "content/renderer/loader/web_url_loader_impl.h"
#include "content/renderer/render_thread_impl.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/mojom/referrer_policy.mojom.h"
#include "third_party/blink/public/platform/web_url_loader_client.h"
#include "third_party/blink/public/platform/web_url_response.h"

namespace content {
namespace {

base::LazyInstance<std::map<int, PluginURLFetcher*> >::Leaky g_fetchers =
    LAZY_INSTANCE_INITIALIZER;

int Start(ResourceDispatcher* resource_dispatcher,
  PluginStreamUrl* plugin_stream,
  const GURL& url,
  const GURL& first_party_for_cookies,
  const std::string& method,
  const char* buf,
  unsigned int len,
  const Referrer& referrer,
  const std::string& range,
  bool notify_redirects,
  bool is_plugin_src_load,
  int routing_id,
  int render_frame_id,
  int render_view_id,
  unsigned long resource_id,
  bool copy_stream_data) {

	static int request_id_counter = 0;
  RequestInfo request_info;
  request_info.method = method;
  request_info.url = url;
  request_info.first_party_for_cookies = first_party_for_cookies;
  request_info.referrer = referrer;
  request_info.load_flags = net::LOAD_NORMAL;
  request_info.request_type = ResourceType::kObject;

  request_info.routing_id = routing_id;
  auto extra_data = base::MakeRefCounted<RequestExtraData>();
  extra_data->set_render_frame_id(render_frame_id);
  extra_data->set_is_main_frame(false);
  request_info.extra_data = std::move(extra_data);

  std::vector<char> body;
  if (method == "POST") {
      bool content_type_found = false;
      std::vector<std::string> names;
      std::vector<std::string> values;
      PluginHost::SetPostData(buf, len, &names, &values, &body);
      for (size_t i = 0; i < names.size(); ++i) {
        if (!request_info.headers.empty())
          request_info.headers += "\r\n";
        request_info.headers += names[i] + ": " + values[i];
        if (base::LowerCaseEqualsASCII(names[i], "content-type"))
          content_type_found = true;
      }

      if (!content_type_found) {
        if (!request_info.headers.empty())
          request_info.headers += "\r\n";
        request_info.headers += "Content-Type: application/x-www-form-urlencoded";
      }
  } else {
    if (!range.empty())
      request_info.headers = std::string("Range: ") + range;
  }

  PluginProcessMsg_CreateLoaderAndStart_Params params;
  params.url = url;
  params.first_party_for_cookies = first_party_for_cookies;
  params.method = method;
  params.buffer = body;
  params.referrer = referrer.url;
  params.referrer_policy = referrer.policy;
  params.range = range;
  params.headers = request_info.headers;
  params.notify_redirects = notify_redirects;
  params.is_plugin_src_load = is_plugin_src_load;
  params.routing_id = routing_id;
  params.render_frame_id = render_frame_id;
  params.routing_id = routing_id;
	params.request_id = ++request_id_counter;
  params.resource_id = resource_id;
  params.copy_stream_data = copy_stream_data;
  PluginThread::current()->Send(new PluginProcessMsg_CreateLoaderAndStart(params));
  return request_id_counter;
}
}

PluginURLFetcher* PluginStreamUrl::GetFetcherFromID(int request_id)
{
    std::map<int, PluginURLFetcher*>::iterator it = g_fetchers.Get().find(request_id);

    if (it != g_fetchers.Get().end())

        return it->second;

    return nullptr;
}

void PluginStreamUrl::RemoveFetcher(int request_id)
{

    std::map<int, PluginURLFetcher*>::iterator it = g_fetchers.Get().find(request_id);

    if (it != g_fetchers.Get().end())
        g_fetchers.Get().erase(it);

}

void PluginStreamUrl::AddFetcher(int request_id, PluginURLFetcher* fetcher)
{
    g_fetchers.Get()[request_id] = fetcher;
}

PluginStreamUrl::PluginStreamUrl(
    unsigned long resource_id,
    const GURL &url,
    PluginInstance *instance,
    bool notify_needed,
    void *notify_data)
    : PluginStream(instance, url.spec().c_str(), notify_needed, notify_data),
      url_(url),
      id_(resource_id),
      request_id_(0) {

  resource_dispatcher_.reset(new ResourceDispatcher());
  canceled_stream_ = false;
}

void PluginStreamUrl::StartFetch(
    const GURL& url,
    const GURL& first_party_for_cookies,
    const std::string& method,
    const char* buf,
    unsigned int len,
    const Referrer& referrer,
    bool notify_redirects,
    bool is_plugin_src_load,
    int routing_id,
    int render_frame_id,
    int render_view_id,
    unsigned long resource_id,
    bool copy_stream_data) {
    LOG(INFO) << "[NPAPI] PluginStreamUrl::StartFetch " << url.spec();
    request_id_ = Start(
        resource_dispatcher_.get(),
        this, url, first_party_for_cookies, method, buf, len,
        referrer, std::string(), notify_redirects,
        is_plugin_src_load, routing_id,
        render_frame_id, render_view_id, resource_id, copy_stream_data);
}

void PluginStreamUrl::URLRedirectResponse(bool allow) {
  if (GetFetcherFromID(request_id_)) {
      GetFetcherFromID(request_id_)->URLRedirectResponse(allow);
  } else {
    instance()->webplugin()->URLRedirectResponse(allow, id_);
  }

  if (allow)
    UpdateUrl(pending_redirect_url_.c_str());
}

void PluginStreamUrl::FetchRange(const std::string& range) {
    PluginURLFetcher* fetcher = GetFetcherFromID(request_id_);

    if (!fetcher)
        return;

    int req_id = Start(
        resource_dispatcher_.get(),
        this, url_, fetcher->first_party_for_cookies(),
        "GET", NULL,
        0, fetcher->referrer(), range, false, false,
        fetcher->origin_pid(),
        fetcher->render_frame_id(),
        fetcher->render_view_id(), id_,
        fetcher->copy_stream_data());

    if (req_id > 0)
        range_request_fetchers_id_.push_back(req_id);
}

bool PluginStreamUrl::Close(NPReason reason) {
  // Protect the stream against it being destroyed or the whole plugin instance
  // being destroyed within the destroy stream handler.
  scoped_refptr<PluginStream> protect(this);
  CancelRequest();
  bool result = PluginStream::Close(reason);
  instance()->RemoveStream(this);
  return result;
}

WebPluginResourceClient* PluginStreamUrl::AsResourceClient() {
  return static_cast<WebPluginResourceClient*>(this);
}

void PluginStreamUrl::CancelRequest() {
  canceled_stream_ = true;

  if (id_ > 0) {
    PluginURLFetcher* fetcher = GetFetcherFromID(request_id_);
    if (fetcher) {
        fetcher->Cancel();
    } else {
      if (instance()->webplugin()) {
        instance()->webplugin()->CancelResource(id_);
      }
    }
    id_ = 0;
  }
  if (instance()->webplugin()) {
    for (size_t i = 0; i < range_requests_.size(); ++i)
      instance()->webplugin()->CancelResource(range_requests_[i]);
  }

  range_requests_.clear();
  for (auto &u : range_request_fetchers_id_) {
    RenderThreadImpl::current()->resource_dispatcher()->RemovePendingRequest(
            u, RenderThreadImpl::current()->main_thread_runner());
  }

  range_request_fetchers_id_.clear();
}

void PluginStreamUrl::WillSendRequest(const GURL& url, int http_status_code) {
  if (notify_needed()) {
    // If the plugin participates in HTTP url redirect handling then notify it.
    if (net::HttpResponseHeaders::IsRedirectResponseCode(http_status_code) &&
        instance()->handles_url_redirects()) {
      pending_redirect_url_ = url.spec();
      instance()->NPP_URLRedirectNotify(url.spec().c_str(), http_status_code,
          notify_data());
      return;
    }
  }
  url_ = url;
  UpdateUrl(url.spec().c_str());
}

void PluginStreamUrl::DidReceiveResponse(const std::string& mime_type,
                                         const std::string& headers,
                                         uint32_t expected_length,
                                         uint32_t last_modified,
                                         bool request_is_seekable) {
  // Protect the stream against it being destroyed or the whole plugin instance
  // being destroyed within the new stream handler.
  scoped_refptr<PluginStream> protect(this);

  bool opened = Open(mime_type,
                     headers,
                     expected_length,
                     last_modified,
                     request_is_seekable);
  if (!opened) {
    CancelRequest();
    instance()->RemoveStream(this);
  } else {
    SetDeferLoading(false);
  }
}

void PluginStreamUrl::DidReceiveData(const char* buffer, int length,
                                     int data_offset) {
  if (!open())
    return;

  // Protect the stream against it being destroyed or the whole plugin instance
  // being destroyed within the write handlers
  scoped_refptr<PluginStream> protect(this);

  if (length > 0) {
    // The PluginStreamUrl instance could get deleted if the plugin fails to
    // accept data in NPP_Write.
    if (Write(const_cast<char*>(buffer), length, data_offset) > 0) {
      SetDeferLoading(false);
    }
  }
}

void PluginStreamUrl::DidFinishLoading(unsigned long resource_id) {
  if (!seekable()) {
    Close(NPRES_DONE);
  } else {
    std::vector<unsigned long>::iterator it_resource = std::find(
        range_requests_.begin(),
        range_requests_.end(),
        resource_id);
    // Resource id must be known to us - either main resource id, or one
    // of the resources, created for range requests.
    DCHECK(resource_id == id_ || it_resource != range_requests_.end());
    // We should notify the plugin about failed/finished requests to ensure
    // that the number of active resource clients does not continue to grow.
    if (instance()->webplugin())
      instance()->webplugin()->CancelResource(resource_id);
    if (it_resource != range_requests_.end())
      range_requests_.erase(it_resource);
  }
}

void PluginStreamUrl::DidFail(unsigned long resource_id) {
  Close(NPRES_NETWORK_ERR);
}

bool PluginStreamUrl::IsMultiByteResponseExpected() {
  return seekable();
}

int PluginStreamUrl::ResourceId() {
  return id_;
}

PluginStreamUrl::~PluginStreamUrl() {
  if (!GetFetcherFromID(request_id_) && instance() && instance()->webplugin()) {
    instance()->webplugin()->ResourceClientDeleted(AsResourceClient());
  }
  for (auto &u : range_request_fetchers_id_) {
      RenderThreadImpl::current()->resource_dispatcher()->RemovePendingRequest(
        u, RenderThreadImpl::current()->main_thread_runner());
  }

  range_request_fetchers_id_.clear();
}

void PluginStreamUrl::AddRangeRequestResourceId(unsigned long resource_id) {
  DCHECK_NE(resource_id, 0u);
  range_requests_.push_back(resource_id);
}

void PluginStreamUrl::SetDeferLoading(bool value) {
  // If we determined that the request had failed via the HTTP headers in the
  // response then we send out a failure notification to the plugin process, as
  // certain plugins don't handle HTTP failure codes correctly.
  if (GetFetcherFromID(request_id_)) {
    if (!value && GetFetcherFromID(request_id_)->pending_failure_notification()) {
      // This object may be deleted now.
      DidFail(id_);
    }
    return;
  }
  if (id_ > 0)
    instance()->webplugin()->SetDeferResourceLoading(id_, value);
  for (size_t i = 0; i < range_requests_.size(); ++i)
    instance()->webplugin()->SetDeferResourceLoading(range_requests_[i],
                                                     value);
}

void PluginStreamUrl::UpdateUrl(const char* url) {
  DCHECK(!open());
  free(const_cast<char*>(stream()->url));
  stream()->url = base::strdup(url);
  pending_redirect_url_.clear();
}

void PluginStreamUrl::FetchedURL(int resource_id,
                                 int response_code,
                                 const std::string& mime,
                                 const std::string& head,
                                 const std::string& data) {

  // being destroyed within the write handlers
  scoped_refptr<PluginStream> protect(this);

  if (response_code == 200 || response_code == 10001) {

    WillSendRequest(url_, 0);
    DidReceiveResponse(mime, head, data.length(), 0, false);
    PluginInstance* pi = instance();
    if (pi && pi->HasStream(this)) {
      DidReceiveData(data.data(), data.length(), 0);
    }
    pi = instance();
    if (pi && pi->HasStream(this)) {
      DidFinishLoading(resource_id);
    }

  } else {
    DidFail(resource_id);
  }

}

}  // namespace content
