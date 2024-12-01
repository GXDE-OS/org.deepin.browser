// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_SSL_SSL_CLIENT_CERTIFICATE_SELECTOR_GM_H_
#define CHROME_BROWSER_SSL_SSL_CLIENT_CERTIFICATE_SELECTOR_GM_H_

#include <memory>

#include "base/callback_forward.h"
#include "build/build_config.h"
#include "net/ssl/client_cert_identity.h"
#include "third_party/boringssl/src/crypto/skf/skf_manager.h"

namespace content {
class ClientCertificateDelegate;
class WebContents;
}

namespace net {
class SSLCertRequestInfo;
}

namespace chrome {
  base::OnceClosure ShowClientSSLPinDialog(
    content::WebContents* web_contents,
    net::SSLCertRequestInfo* cert_request_info,
    std::unique_ptr<content::ClientCertificateDelegate> delegate,
    skfmodule * in_skf_module,
    X509_NAME * in_issuer);

  bool CheckModulesAndDevices(content::WebContents* web_contents,
    net::SSLCertRequestInfo* cert_request_info,
    skfmodule** out_skf_module,X509_NAME **out_issuer);
}   //namespace chrome

#endif
