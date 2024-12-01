// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_CHILD_NPAPI_PLUGIN_STREAM_URL_H_
#define CONTENT_CHILD_NPAPI_PLUGIN_STREAM_URL_H_

#include <stdint.h>
#include <vector>

#include "content/child/npapi/plugin_stream.h"
#include "content/child/npapi/webplugin_resource_client.h"
#include "url/gurl.h"

namespace content {
class PluginInstance;
class PluginURLFetcher;
struct Referrer;

class ResourceDispatcher;

// A NPAPI Stream based on a URL.
class PluginStreamUrl : public PluginStream,
                        public WebPluginResourceClient {
 public:
     static PluginURLFetcher* GetFetcherFromID(int request_id);
     static void RemoveFetcher(int request_id);
     static void AddFetcher(int request_id, PluginURLFetcher* fetcher);

  // Create a new stream for sending to the plugin by fetching
  // a URL. If notifyNeeded is set, then the plugin will be notified
  // when the stream has been fully sent to the plugin.  Initialize
  // must be called before the object is used.
  PluginStreamUrl(unsigned long resource_id,
                  const GURL &url,
                  PluginInstance *instance,
                  bool notify_needed,
                  void *notify_data);

  void StartFetch(
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
      bool copy_stream_data);

  void URLRedirectResponse(bool allow);

  void FetchRange(const std::string& range);

  // Stop sending the stream to the client.
  // Overrides the base Close so we can cancel our fetching the URL if
  // it is still loading.
  bool Close(NPReason reason) override;
  WebPluginResourceClient* AsResourceClient() override;
  void CancelRequest() override;

  // WebPluginResourceClient methods
  void WillSendRequest(const GURL& url, int http_status_code) override;
  void DidReceiveResponse(const std::string& mime_type,
                          const std::string& headers,
                          uint32_t expected_length,
                          uint32_t last_modified,
                          bool request_is_seekable) override;
  void DidReceiveData(const char* buffer, int length, int data_offset) override;
  void DidFinishLoading(unsigned long resource_id) override;
  void DidFail(unsigned long resource_id) override;
  bool IsMultiByteResponseExpected() override;
  int ResourceId() override;
  void AddRangeRequestResourceId(unsigned long resource_id) override;
  void FetchedURL(
                 int resource_id,
                 int response_code,
                 const std::string& mime,
                 const std::string& head,
                 const std::string& data);


 protected:
  ~PluginStreamUrl() override;

 private:
  void SetDeferLoading(bool value);

  // In case of a redirect, this can be called to update the url.  But it must
  // be called before Open().
  void UpdateUrl(const char* url);

  GURL url_;
  unsigned long id_;

  bool canceled_stream_;

  std::unique_ptr<ResourceDispatcher> resource_dispatcher_;

  // Ids of additional resources requested via range requests issued on
  // seekable streams.
  // This is used when we're loading resources through the renderer, i.e. not
  // using plugin_url_fetcher_.
  std::vector<unsigned long> range_requests_;

  // If the plugin participates in HTTP URL redirect handling then this member
  // holds the url being redirected to while we wait for the plugin to make a
  // decision on whether to allow or deny the redirect.
  std::string pending_redirect_url_;

  int request_id_;
  std::vector<int> range_request_fetchers_id_;

  DISALLOW_COPY_AND_ASSIGN(PluginStreamUrl);
};

}  // namespace content

#endif  // CONTENT_CHILD_NPAPI_PLUGIN_STREAM_URL_H_
