// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DDE_DDE_VM_COMPOSITING_CLIENT_H_
#define UOS_DDE_DDE_VM_COMPOSITING_CLIENT_H_

#include <memory>
#include <string>

#include "base/component_export.h"
#include "base/macros.h"
#include "uos/dbus_client.h"

namespace dbus{

namespace uos {

// DdeVMCompositingClient is used to dde vm compositing connection with the
// dde vm in uos.
class COMPONENT_EXPORT(UOS_DBUS) DdeVMCompositingClient : public DBusClient {
 public:
  ~DdeVMCompositingClient() override;

  // Creates an instance of DdeVMCompositingClient.
  static std::unique_ptr<DdeVMCompositingClient> Create();

  //  获取当前的uos 系统的窗口特效
  //  true 开启
  //  false 关闭
  virtual bool getCompositingEnabled() = 0;

 protected:
  DdeVMCompositingClient();

 private:
  DISALLOW_COPY_AND_ASSIGN(DdeVMCompositingClient);
};

}  // namespace uos

}  // namespace dbus

#endif  // UOS_DDE_DDE_VM_COMPOSITING_CLIENT_H_
