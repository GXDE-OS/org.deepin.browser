// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/child/request_info.h"

namespace content {

RequestInfo::RequestInfo()
    : load_flags(0),
      requestor_pid(0),
      request_type(ResourceType::kMainFrame),
      fetch_request_context_type(REQUEST_CONTEXT_TYPE_UNSPECIFIED),
      //fetch_frame_type(network::mojom::RequestContextFrameType::kNone),
      priority(net::LOW),
      request_context(0),
      appcache_host_id(0),
      routing_id(0),
      download_to_file(false),
      has_user_gesture(false),
      should_reset_appcache(false),
      fetch_request_mode(network::mojom::RequestMode::kNoCors),
      fetch_credentials_mode(network::mojom::CredentialsMode::kOmit),
      fetch_redirect_mode(network::mojom::RedirectMode::kFollow),
      enable_load_timing(false),
      enable_upload_progress(false),
      do_not_prompt_for_login(false),
      report_raw_headers(false),
      extra_data(nullptr),
      previews_state(blink::WebURLRequest::kPreviewsUnspecified) {}

RequestInfo::~RequestInfo() {}

}  // namespace content
