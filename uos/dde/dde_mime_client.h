// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DDE_DDE_MIME_CLIENT_H
#define UOS_DDE_DDE_MIME_CLIENT_H

#include <memory>
#include <string>

#include "base/component_export.h"
#include "base/macros.h"
#include "uos/dbus_client.h"

namespace dbus {
    
namespace uos {
    // D-Bus clients used only in the browser process.
// TODO(jamescook): Move this under //chrome/browser. http://crbug.com/647367
class COMPONENT_EXPORT(UOS_DBUS) DdeMimeClient : public DBusClient {
 public:
  // Creates real implementations if |use_real_clients| is true and fakes
  // otherwise. Fakes are used when running on Linux desktop and in tests.
  ~DdeMimeClient() override;

  // Creates an instance of DdeMimeClient.
  static std::unique_ptr<DdeMimeClient> Create();

  //  设置 为 uos系统默认的浏览器
  virtual bool SetUosDefaultBrowser() = 0;

  //  是否为uos系统默认的浏览器
  virtual bool IsUosDefaultBrowser() = 0;

 protected:
  DdeMimeClient();

 private:
  DISALLOW_COPY_AND_ASSIGN(DdeMimeClient);
};

}  // namespace uos
} // namespace dbus
#endif  // UOS_DDE_DDE_MIME_CLIENT_H
