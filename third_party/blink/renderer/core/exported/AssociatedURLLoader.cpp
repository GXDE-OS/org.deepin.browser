/*
 * Copyright (C) 2010, 2011, 2012 Google Inc. All rights reserved.
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
#include "third_party/blink/public/web/AssociatedURLLoader.h"

#include "base/memory/ptr_util.h"
#include "third_party/blink/public/platform/web_cors.h"
#include "third_party/blink/public/platform/web_http_header_set.h"
#include "third_party/blink/public/platform/web_http_header_visitor.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_loader_client.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/web/WebDataSource.h"
#include "third_party/blink/renderer/core/dom/context_lifecycle_observer.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/loader/threadable_loading_context.h"
#include "third_party/blink/renderer/core/loader/document_threadable_loader.h"
#include "third_party/blink/renderer/core/loader/document_threadable_loader_client.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_request.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include <limits.h>
#include <memory>

namespace blink {

namespace {

class HTTPRequestHeaderValidator : public WebHTTPHeaderVisitor {
  WTF_MAKE_NONCOPYABLE(HTTPRequestHeaderValidator);

 public:
  HTTPRequestHeaderValidator() : m_isSafe(true) {}
  ~HTTPRequestHeaderValidator() override {}

  void VisitHeader(const WebString& name, const WebString& value) override;
  bool IsSafe() const { return m_isSafe; }

 private:
  bool m_isSafe;
};

void HTTPRequestHeaderValidator::VisitHeader(const WebString& name,
                                             const WebString& value) {
  m_isSafe = m_isSafe && IsValidHTTPToken(name) &&
             !CORS::IsForbiddenHeaderName(name) &&
             IsValidHTTPHeaderValue(value);
}

}  // namespace

// This class bridges the interface differences between WebCore and WebKit
// loader clients.
// It forwards its ThreadableLoaderClient notifications to a WebURLLoaderClient.
class AssociatedURLLoader::ClientAdapter final
    : public DocumentThreadableLoaderClient {
  WTF_MAKE_NONCOPYABLE(ClientAdapter);

 public:
  static std::unique_ptr<ClientAdapter> create(AssociatedURLLoader*,
                                               WebURLLoaderClient*,
                                               const WebURLLoaderOptions&);

  // ThreadableLoaderClient
  void DidSendData(unsigned long long /*bytesSent*/,
                   unsigned long long /*totalBytesToBeSent*/) override;
  void DidReceiveResponse(unsigned long,
                          const ResourceResponse&,
                          std::unique_ptr<WebDataConsumerHandle>) override;
  void DidDownloadData(int /*dataLength*/) override;
  void DidReceiveData(const char*, unsigned /*dataLength*/) override;
  void DidReceiveCachedMetadata(const char*, int /*dataLength*/) override;
  void DidFinishLoading(unsigned long /*identifier*/) override;
  void DidFail(const ResourceError&) override;
  void DidFailRedirectCheck() override;

  // DocumentThreadableLoaderClient
  bool WillFollowRedirect(const KURL& new_url,
                          const ResourceResponse&) override;

  // Sets an error to be reported back to the client, asychronously.
  void setDelayedError(const ResourceError&);

  // Enables forwarding of error notifications to the WebURLLoaderClient. These
  // must be deferred until after the call to
  // AssociatedURLLoader::loadAsynchronously() completes.
  void enableErrorNotifications();

  // Stops loading and releases the DocumentThreadableLoader as early as
  // possible.
  WebURLLoaderClient* releaseClient() {
    WebURLLoaderClient* client = m_client;
    m_client = nullptr;
    return client;
  }

 private:
  ClientAdapter(AssociatedURLLoader*,
                WebURLLoaderClient*,
                const WebURLLoaderOptions&);

  void notifyError(TimerBase*);

  AssociatedURLLoader* m_loader;
  WebURLLoaderClient* m_client;
  WebURLLoaderOptions m_options;
  WebURLError m_error;

  TaskRunnerTimer<ClientAdapter> m_errorTimer;
  bool m_enableErrorNotifications;
  bool m_didFail;
};

std::unique_ptr<AssociatedURLLoader::ClientAdapter>
AssociatedURLLoader::ClientAdapter::create(AssociatedURLLoader* loader,
                                           WebURLLoaderClient* client,
                                           const WebURLLoaderOptions& options) {
  return base::WrapUnique(new ClientAdapter(loader, client, options));
}

AssociatedURLLoader::ClientAdapter::ClientAdapter(
    AssociatedURLLoader* loader,
    WebURLLoaderClient* client,
    const WebURLLoaderOptions& options)
    : m_loader(loader),
      m_client(client),
      m_options(options),
      m_error(net::ERR_FAILED, WebURL()),
      m_errorTimer(base::ThreadTaskRunnerHandle::Get(), this,
                   &ClientAdapter::notifyError),
      m_enableErrorNotifications(false),
      m_didFail(false) {
  DCHECK(m_loader);
  DCHECK(m_client);
}

bool AssociatedURLLoader::ClientAdapter::WillFollowRedirect(
    const KURL& new_url,
    const ResourceResponse& redirectResponse) {
  if (!m_client)
    return true;

  WrappedResourceResponse wrappedRedirectResponse(redirectResponse);
  return m_client->WillFollowRedirect(m_loader, WebURL(new_url),
                                      wrappedRedirectResponse);
}

void AssociatedURLLoader::ClientAdapter::DidSendData(
    unsigned long long bytesSent,
    unsigned long long totalBytesToBeSent) {
  if (!m_client)
    return;

  m_client->DidSendData(m_loader, bytesSent, totalBytesToBeSent);
}

void AssociatedURLLoader::ClientAdapter::DidReceiveResponse(
    unsigned long,
    const ResourceResponse& response,
    std::unique_ptr<WebDataConsumerHandle> handle) {
  DCHECK(!handle);
  if (!m_client)
    return;

  if (m_options.exposeAllResponseHeaders ||
      m_options.crossOriginRequestPolicy !=
          WebURLLoaderOptions::CrossOriginRequestPolicyUseAccessControl) {
    // Use the original ResourceResponse.
    m_client->DidReceiveResponse(m_loader, WrappedResourceResponse(response));
    return;
  }

  WebHTTPHeaderSet exposedHeaders = WebCORS::ExtractCorsExposedHeaderNamesList(
      network::mojom::FetchCredentialsMode::kOmit, WrappedResourceResponse(response));
  WebHTTPHeaderSet blockedHeaders;
  for (const auto& header : response.HttpHeaderFields()) {
    if (FetchUtils::IsForbiddenResponseHeaderName(header.key) ||
        (!WebCORS::IsOnAccessControlResponseHeaderWhitelist(header.key) &&
         exposedHeaders.find(header.key.Ascii().data()) ==
             exposedHeaders.end()))
      blockedHeaders.insert(header.key.Ascii().data());
  }

  if (blockedHeaders.empty()) {
    // Use the original ResourceResponse.
    m_client->DidReceiveResponse(m_loader, WrappedResourceResponse(response));
    return;
  }

  // If there are blocked headers, copy the response so we can remove them.
  WebURLResponse validatedResponse = WrappedResourceResponse(response);
  for (const auto& header : blockedHeaders)
    validatedResponse.ClearHTTPHeaderField(WebString::FromASCII(header));
  m_client->DidReceiveResponse(m_loader, validatedResponse);
}

void AssociatedURLLoader::ClientAdapter::DidDownloadData(int dataLength) {
  if (!m_client)
    return;

  m_client->DidDownloadData(m_loader, dataLength, -1);
}

void AssociatedURLLoader::ClientAdapter::DidReceiveData(const char* data,
                                                        unsigned dataLength) {
  if (!m_client)
    return;

  CHECK_LE(dataLength, static_cast<unsigned>(std::numeric_limits<int>::max()));

  m_client->DidReceiveData(m_loader, data, dataLength);
}

void AssociatedURLLoader::ClientAdapter::DidReceiveCachedMetadata(
    const char* data,
    int dataLength) {
  if (!m_client)
    return;

  m_client->DidReceiveCachedMetadata(m_loader, data, dataLength);
}

void AssociatedURLLoader::ClientAdapter::DidFinishLoading(
    unsigned long identifier) {
  if (!m_client)
    return;

  m_loader->clientAdapterDone();

  releaseClient()->DidFinishLoading(
      m_loader, base::TimeTicks(), WebURLLoaderClient::kUnknownEncodedDataLength,
      0, 0, false);
  // |this| may be dead here.
}

void AssociatedURLLoader::ClientAdapter::DidFail(const ResourceError& error) {
  if (!m_client)
    return;

  m_loader->clientAdapterDone();

  m_didFail = true;
  m_error = WebURLError(error);
  if (m_enableErrorNotifications)
    notifyError(&m_errorTimer);
}

void AssociatedURLLoader::ClientAdapter::DidFailRedirectCheck() {
  DidFail(ResourceError::Failure(KURL()));
}

void AssociatedURLLoader::ClientAdapter::enableErrorNotifications() {
  m_enableErrorNotifications = true;
  // If an error has already been received, start a timer to report it to the
  // client after AssociatedURLLoader::loadAsynchronously has returned to the
  // caller.
  if (m_didFail)
    m_errorTimer.StartOneShot(TimeDelta(), FROM_HERE);
}

void AssociatedURLLoader::ClientAdapter::notifyError(TimerBase* timer) {
  DCHECK_EQ(timer, &m_errorTimer);

  if (m_client)
    releaseClient()->DidFail(m_loader, m_error, 0, 0, 0);
  // |this| may be dead here.
}

class AssociatedURLLoader::Observer final : public GarbageCollected<Observer>,
                                            public ContextLifecycleObserver {
  USING_GARBAGE_COLLECTED_MIXIN(Observer);

 public:
  Observer(AssociatedURLLoader* parent, Document* document)
      : ContextLifecycleObserver(document), m_parent(parent) {}

  void dispose() {
    m_parent = nullptr;
    ClearContext();
  }

  void ContextDestroyed(ExecutionContext*) override {
    if (m_parent)
      m_parent->documentDestroyed();
  }

  void Trace(blink::Visitor* visitor) override {
    ContextLifecycleObserver::Trace(visitor);
  }

  AssociatedURLLoader* m_parent;
};

AssociatedURLLoader::AssociatedURLLoader(WebLocalFrameImpl* frameImpl,
                                         const WebURLLoaderOptions& options)
    : m_client(nullptr),
      m_options(options),
      m_observer(new Observer(this, frameImpl->GetFrame()->GetDocument())) {}

AssociatedURLLoader::~AssociatedURLLoader() {
  Cancel();
}

void AssociatedURLLoader::LoadSynchronously(const WebURLRequest&,
                                                 WebURLLoaderClient*,
                                                 WebURLResponse&,
                                                 base::Optional<WebURLError>&,
                                                 WebData&,
                                                 int64_t& encoded_data_length,
                                                 int64_t& encoded_body_length,
                                                 WebBlobInfo& downloaded_blob) {
  DCHECK(0);  // Synchronous loading is not supported.
}

void AssociatedURLLoader::LoadAsynchronously(const WebURLRequest& request,
                                             WebURLLoaderClient* client) {
  DCHECK(!m_client);
  DCHECK(!m_loader);
  DCHECK(!m_clientAdapter);

  DCHECK(client);

  bool allowLoad = true;
  WebURLRequest newRequest(request);
  if (m_options.untrustedHTTP) {
    WebString method = newRequest.HttpMethod();
    allowLoad = m_observer && IsValidHTTPToken(method) &&
                !FetchUtils::IsForbiddenMethod(method);
    if (allowLoad) {
      newRequest.SetHTTPMethod(FetchUtils::NormalizeMethod(method));
      HTTPRequestHeaderValidator validator;
      newRequest.VisitHTTPHeaderFields(&validator);
      allowLoad = validator.IsSafe();
    }
  }

  m_client = client;
  m_clientAdapter = ClientAdapter::create(this, client, m_options);

  if (allowLoad) {
    ThreadableLoaderOptions options;
    ResourceLoaderOptions resourceLoaderOptions;
    resourceLoaderOptions.data_buffering_policy = kDoNotBufferData;

    const ResourceRequest& webcoreRequest = newRequest.ToResourceRequest();
    if (webcoreRequest.GetRequestContext() ==
        WebURLRequest::kRequestContextUnspecified) {
      // FIXME: We load URLs without setting a TargetType (and therefore a
      // request context) in several places in content/
      // (P2PPortAllocatorSession::AllocateLegacyRelaySession, for example).
      // Remove this once those places are patched up.
      newRequest.SetRequestContext(WebURLRequest::kRequestContextInternal);
    }

    Document* document = ToDocument(m_observer->LifecycleContext());
    DCHECK(document);
    m_loader = DocumentThreadableLoader::Create(
        *ThreadableLoadingContext::Create(*document), m_clientAdapter.get(), options, resourceLoaderOptions);
    m_loader->Start(webcoreRequest);
  }

  if (!m_loader) {
    // FIXME: return meaningful error codes.
    m_clientAdapter->DidFail(ResourceError::Failure(KURL()));
  }
  m_clientAdapter->enableErrorNotifications();
}

void AssociatedURLLoader::Cancel() {
  disposeObserver();
  cancelLoader();
  releaseClient();
}

void AssociatedURLLoader::clientAdapterDone() {
  disposeObserver();
  releaseClient();
}

void AssociatedURLLoader::cancelLoader() {
  if (!m_clientAdapter)
    return;

  // Prevent invocation of the WebURLLoaderClient methods.
  m_clientAdapter->releaseClient();

  if (m_loader) {
    m_loader->Cancel();
    m_loader = nullptr;
  }
  m_clientAdapter.reset();
}

void AssociatedURLLoader::SetDefersLoading(bool defersLoading) {
  if (m_loader)
    m_loader->SetDefersLoading(defersLoading);
}

void AssociatedURLLoader::documentDestroyed() {
  disposeObserver();
  cancelLoader();

  if (!m_client)
    return;

  releaseClient()->DidFail(this, ResourceError::Failure(blink::KURL()), 0, 0, 0);
  // |this| may be dead here.
}

void AssociatedURLLoader::disposeObserver() {
  if (!m_observer)
    return;

  // TODO(tyoshino): Remove this assert once Document is fixed so that
  // contextDestroyed() is invoked for all kinds of Documents.
  //
  // Currently, the method of detecting Document destruction implemented here
  // doesn't work for all kinds of Documents. In case we reached here after
  // the Oilpan is destroyed, we just crash the renderer process to prevent
  // UaF.
  //
  // We could consider just skipping the rest of code in case
  // ThreadState::current() is null. However, the fact we reached here
  // without cancelling the loader means that it's possible there're some
  // non-Blink non-on-heap objects still facing on-heap Blink objects. E.g.
  // there could be a WebURLLoader instance behind the
  // DocumentThreadableLoader instance. So, for safety, we chose to just
  // crash here.
  CHECK(ThreadState::Current());

  m_observer->dispose();
  m_observer = nullptr;
}

}  // namespace blink
