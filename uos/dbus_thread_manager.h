// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DBUS_THREAD_MANAGER_H_
#define UOS_DBUS_THREAD_MANAGER_H_

#include <memory>
#include <string>

#include "base/callback.h"
#include "base/component_export.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"

namespace base {
class Thread;
}  // namespace base

namespace dbus {
class Bus;

namespace uos {

class DBusClientsBrowser;

class DdeAppearanceThemeClient;
class DdeMimeClient;
class DdeVMCompositingClient;
class DdePasswordAuthClient;
class DdeManualClient;

// THIS CLASS IS BEING DEPRECATED. See README.md for guidelines and
// https://crbug.com/647367 for details.
//
// DBusThreadManager manages the D-Bus thread, the thread dedicated to
// handling asynchronous D-Bus operations.
//
// This class also manages D-Bus connections and D-Bus clients, which
// depend on the D-Bus thread to ensure the right order of shutdowns for
// the D-Bus thread, the D-Bus connections, and the D-Bus clients.
class COMPONENT_EXPORT(UOS_DBUS) DBusThreadManager {
 public:  
  // Returns true if DBusThreadManager has been initialized. Call this to
  // avoid initializing + shutting down DBusThreadManager more than once.
  static bool IsInitialized();

  // Destroys the global instance.
  static void Shutdown();

  // Gets the global instance. Initialize() must be called first.
  static DBusThreadManager* Get();
  
  // Returns various D-Bus bus instances, owned by DBusThreadManager.
  Bus* GetSessionBus();

  // All returned objects are owned by DBusThreadManager.  Do not use these
  // pointers after DBusThreadManager has been shut down.
  // TODO(jamescook): Replace this with calls to FooClient::Get().
  // http://crbug.com/647367
  DdeVMCompositingClient* GetDdeVMCompositingClient();
  DdeAppearanceThemeClient* GetDdeAppearanceThemeClient();
  DdeMimeClient * GetDdeMimeClient();
  DdeManualClient * GetDdeManualClient();
  DdePasswordAuthClient * GetDdePasswordAuthClient();

  // Initializes all currently stored DBusClients with the system bus and
  // performs additional setup.
  static void Initialize();

 private:
   explicit DBusThreadManager();
  ~DBusThreadManager();

  void InitializeClients();

  std::unique_ptr<base::Thread> dbus_thread_;
  scoped_refptr<Bus> session_bus_;

  // Clients used only by the browser process. Null in other processes.
  std::unique_ptr<DBusClientsBrowser> clients_browser_;

  DISALLOW_COPY_AND_ASSIGN(DBusThreadManager);
};

}  // namespace uos

}  // namespace dbus
#endif  // UOS_DBUS_DBUS_THREAD_MANAGER_H_
