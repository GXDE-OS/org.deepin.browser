// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DBUS_CLIENTS_BROWSER_H_
#define UOS_DBUS_CLIENTS_BROWSER_H_

#include <memory>

#include "base/component_export.h"
#include "base/macros.h"

namespace dbus {
class Bus;

namespace uos {

class DdeAppearanceThemeClient;
class DdeMimeClient;
class DdeVMCompositingClient;
class DdeManualClient;
class DdePasswordAuthClient;

// D-Bus clients used only in the browser process.
// TODO(jamescook): Move this under //chrome/browser. http://crbug.com/647367
class COMPONENT_EXPORT(UOS_DBUS) DBusClientsBrowser {
 public:
  // Creates real implementations if |use_real_clients| is true and fakes
  // otherwise. Fakes are used when running on Linux desktop and in tests.
  explicit DBusClientsBrowser();
  ~DBusClientsBrowser();

  void InitializeUosSession(Bus* session_bus);

 public:
   static std::string GetUOSBusAddress();

 private:
  friend class DBusThreadManager;

  std::unique_ptr<DdeAppearanceThemeClient> dde_appearance_theme_client_;
  std::unique_ptr<DdeMimeClient> dde_mime_client_;
  std::unique_ptr<DdeVMCompositingClient> dde_vm_compositing_client_;
  std::unique_ptr<DdeManualClient> dde_manual_client_;
  std::unique_ptr<DdePasswordAuthClient> dde_password_auth_client_;

  DISALLOW_COPY_AND_ASSIGN(DBusClientsBrowser);
};

}  // namespace uos
} // namespace dbus
#endif  // CHROMEUOS_DBUS_DBUS_CLIENTS_BROWSER_H_
