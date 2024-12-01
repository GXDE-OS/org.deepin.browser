// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/platform/web_url_loader_test_delegate.h"

#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_loader.h"
#include "third_party/blink/public/platform/web_url_loader_client.h"
#include "third_party/blink/public/platform/web_url_request.h"

namespace blink {

WebURLLoaderTestDelegate::WebURLLoaderTestDelegate() = default;

WebURLLoaderTestDelegate::~WebURLLoaderTestDelegate() = default;

void WebURLLoaderTestDelegate::DidReceiveResponse(
    WebURLLoaderClient* original_client,
    const WebURLResponse& response) {
#if defined(USE_UNIONTECH_NPAPI)
  original_client->DidReceiveResponse(0, response);
#else
  original_client->DidReceiveResponse(response);
#endif
}

void WebURLLoaderTestDelegate::DidReceiveData(
    WebURLLoaderClient* original_client,
    const char* data,
    int data_length) {
#if defined(USE_UNIONTECH_NPAPI)
  original_client->DidReceiveData(0, data, data_length);
#else
  original_client->DidReceiveData(data, data_length);
#endif
}

void WebURLLoaderTestDelegate::DidFail(WebURLLoaderClient* original_client,
                                       const WebURLError& error,
                                       int64_t total_encoded_data_length,
                                       int64_t total_encoded_body_length,
                                       int64_t total_decoded_body_length) {
#if defined(USE_UNIONTECH_NPAPI)
  original_client->DidFail(0, error, total_encoded_data_length,
                           total_encoded_body_length,
                           total_decoded_body_length);
#else
  original_client->DidFail(error, total_encoded_data_length,
                           total_encoded_body_length,
                           total_decoded_body_length);
#endif
}

void WebURLLoaderTestDelegate::DidFinishLoading(
    WebURLLoaderClient* original_client,
    base::TimeTicks finish_time,
    int64_t total_encoded_data_length,
    int64_t total_encoded_body_length,
    int64_t total_decoded_body_length) {
#if defined(USE_UNIONTECH_NPAPI)
  original_client->DidFinishLoading(nullptr, finish_time, total_encoded_data_length,
                                    total_encoded_body_length,
                                    total_decoded_body_length, false);
#else
  original_client->DidFinishLoading(finish_time, total_encoded_data_length,
                                    total_encoded_body_length,
                                    total_decoded_body_length, false);
#endif
}

}  // namespace blink
