// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DDE_DDE_PASSWORD_AUTH_CLIENT_H_
#define UOS_DDE_DDE_PASSWORD_AUTH_CLIENT_H_

#include <memory>
#include <string>

#include "base/component_export.h"
#include "base/macros.h"
#include "uos/dbus_client.h"

namespace dbus{

namespace uos {

class COMPONENT_EXPORT(UOS_DBUS) DdePasswordAuthClient : public DBusClient {
 public:
  ~DdePasswordAuthClient() override;

  // Creates an instance of DdePasswordAuthClient.
  static std::unique_ptr<DdePasswordAuthClient> Create();

  virtual bool browserCheckAuthorization() = 0;

 protected:
  DdePasswordAuthClient();

 private:
  DISALLOW_COPY_AND_ASSIGN(DdePasswordAuthClient);
};

}  // namespace uos

}  // namespace dbus

#endif  // UOS_DDE_DDE_PASSWORD_AUTH_CLIENT_H_
