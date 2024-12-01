/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/exported/WebDataSourceImpl.h"

#include <memory>
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/subresource_filter.h"
#include "third_party/blink/public/platform/web_document_subresource_filter.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/platform/modules/service_worker/web_service_worker_network_provider.h"

#if defined(USE_UNIONTECH_NPAPI)
#include "third_party/blink/renderer/core/frame/WebPluginLoadObserver.h"
#endif

namespace blink {

#if defined(USE_UNIONTECH_NPAPI)
static std::unique_ptr<WebPluginLoadObserver>& nextPluginLoadObserver()
{
    DEFINE_STATIC_LOCAL(std::unique_ptr<WebPluginLoadObserver>, nextPluginLoadObserver, ());
    return nextPluginLoadObserver;
}

std::unique_ptr<WebPluginLoadObserver> WebDataSourceImpl::releasePluginLoadObserver()
{
    return base::WrapUnique(m_pluginLoadObserver.release());
}

void WebDataSourceImpl::setNextPluginLoadObserver(std::unique_ptr<WebPluginLoadObserver> observer)
{
    nextPluginLoadObserver() = std::move(observer);
}

#endif

WebDataSourceImpl* WebDataSourceImpl::Create(
    LocalFrame* frame,
    const ResourceRequest& request,
    const SubstituteData& data,
    ClientRedirectPolicy client_redirect_policy) {
  DCHECK(frame);

  return new WebDataSourceImpl(frame, request, data, client_redirect_policy);
}

const WebURLRequest& WebDataSourceImpl::OriginalRequest() const {
  return original_request_wrapper_;
}

const WebURLRequest& WebDataSourceImpl::GetRequest() const {
  return request_wrapper_;
}

const WebURLResponse& WebDataSourceImpl::GetResponse() const {
  return response_wrapper_;
}

bool WebDataSourceImpl::HasUnreachableURL() const {
  return !DocumentLoader::UnreachableURL().IsEmpty();
}

WebURL WebDataSourceImpl::UnreachableURL() const {
  return DocumentLoader::UnreachableURL();
}

void WebDataSourceImpl::AppendRedirect(const WebURL& url) {
  DocumentLoader::AppendRedirect(url);
}

void WebDataSourceImpl::UpdateNavigation(TimeTicks redirect_start_time,
                                         TimeTicks redirect_end_time,
                                         TimeTicks fetch_start_time,
                                         bool has_redirect) {
  // Updates the redirection timing if there is at least one redirection
  // (between two URLs).
  if (has_redirect) {
    GetTiming().SetRedirectStart(redirect_start_time);
    GetTiming().SetRedirectEnd(redirect_end_time);
  }
  GetTiming().SetFetchStart(fetch_start_time);
}

void WebDataSourceImpl::RedirectChain(WebVector<WebURL>& result) const {
  result.Assign(redirect_chain_);
}

bool WebDataSourceImpl::IsClientRedirect() const {
  return DocumentLoader::IsClientRedirect();
}

bool WebDataSourceImpl::ReplacesCurrentHistoryItem() const {
  return DocumentLoader::ReplacesCurrentHistoryItem();
}

WebNavigationType WebDataSourceImpl::GetNavigationType() const {
  return DocumentLoader::GetNavigationType();
}

WebDataSource::ExtraData* WebDataSourceImpl::GetExtraData() const {
  return extra_data_.get();
}

void WebDataSourceImpl::SetExtraData(ExtraData* extra_data) {
  // extraData can't be a std::unique_ptr because setExtraData is a WebKit API
  // function.
  extra_data_ = base::WrapUnique(extra_data);
}

void WebDataSourceImpl::SetNavigationStartTime(TimeTicks navigation_start) {
  GetTiming().SetNavigationStart(navigation_start);
}

WebDataSourceImpl::WebDataSourceImpl(
    LocalFrame* frame,
    const ResourceRequest& request,
    const SubstituteData& data,
    ClientRedirectPolicy client_redirect_policy)
    : DocumentLoader(frame, request, data, client_redirect_policy,
                     base::UnguessableToken::Create()),
      original_request_wrapper_(DocumentLoader::OriginalRequest()),
      request_wrapper_(DocumentLoader::GetRequest()),
#if defined(USE_UNIONTECH_NPAPI)
      response_wrapper_(DocumentLoader::GetResponse()) {
    if (!nextPluginLoadObserver())
        return;
    // When a new frame is created, it initially gets a data source for an
    // empty document. Then it is navigated to the source URL of the
    // frame, which results in a second data source being created. We want
    // to wait to attach the WebPluginLoadObserver to that data source.
    if (request.Url().IsEmpty())
        return;

    DCHECK(nextPluginLoadObserver()->url() == WebURL(request.Url()));
    m_pluginLoadObserver = std::unique_ptr<WebPluginLoadObserver>(nextPluginLoadObserver().release());
}
#else
      response_wrapper_(DocumentLoader::GetResponse()) {}
#endif

WebDataSourceImpl::~WebDataSourceImpl() {
  // Verify that detachFromFrame() has been called.
  DCHECK(!extra_data_);
}

void WebDataSourceImpl::DetachFromFrame() {
  DocumentLoader::DetachFromFrame();
  extra_data_.reset();
#if defined(USE_UNIONTECH_NPAPI)
  m_pluginLoadObserver.reset();
#endif
}

void WebDataSourceImpl::SetSubresourceFilter(
    WebDocumentSubresourceFilter* subresource_filter) {
  DocumentLoader::SetSubresourceFilter(SubresourceFilter::Create(
      *GetFrame()->GetDocument(), base::WrapUnique(subresource_filter)));
}

void WebDataSourceImpl::SetServiceWorkerNetworkProvider(
    std::unique_ptr<WebServiceWorkerNetworkProvider> provider) {
  DocumentLoader::SetServiceWorkerNetworkProvider(std::move(provider));
}

WebServiceWorkerNetworkProvider*
WebDataSourceImpl::GetServiceWorkerNetworkProvider() {
  return DocumentLoader::GetServiceWorkerNetworkProvider();
}

void WebDataSourceImpl::SetSourceLocation(
    const WebSourceLocation& source_location) {
  std::unique_ptr<SourceLocation> location =
      SourceLocation::Create(source_location.url, source_location.line_number,
                             source_location.column_number, nullptr);
  DocumentLoader::SetSourceLocation(std::move(location));
}

void WebDataSourceImpl::ResetSourceLocation() {
  DocumentLoader::SetSourceLocation(nullptr);
}

void WebDataSourceImpl::Trace(blink::Visitor* visitor) {
  DocumentLoader::Trace(visitor);
}

}  // namespace blink
