// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "uos/dbus_thread_manager.h"
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/message_loop/message_pump_type.h"
#include "base/system/sys_info.h"
#include "base/threading/thread.h"
#include "dbus/bus.h"
#include "uos/dbus_clients_browser.h"
#include "uos/dde/dde_appearance_theme_client.h"
#include "uos/dde/dde_mime_client.h"
#include "uos/dde/dde_vm_compositing_client.h"
#include "uos/dde/dde_help_client.h"

namespace dbus {

namespace uos {

static DBusThreadManager * g_dbus_thread_manager = nullptr;

DBusThreadManager::DBusThreadManager() {
  clients_browser_.reset(new DBusClientsBrowser);
  
    // Create the D-Bus thread.
  base::Thread::Options thread_options;
  thread_options.message_pump_type = base::MessagePumpType::IO;
  dbus_thread_.reset(new base::Thread("D-Bus thread"));
  dbus_thread_->StartWithOptions(thread_options);
  {
    // Create the connection to the session bus.
    Bus::Options session_bus_options;
    session_bus_options.bus_type = Bus::SESSION;
    session_bus_options.connection_type = Bus::PRIVATE;
    session_bus_options.dbus_task_runner = dbus_thread_->task_runner();
    session_bus_ = new Bus(session_bus_options);
  }
}

DBusThreadManager::~DBusThreadManager() {
  if (session_bus_.get())
    session_bus_->ShutdownOnDBusThreadAndBlock();

  // Stop the D-Bus thread.
  if (dbus_thread_)
    dbus_thread_->Stop();
}

Bus* DBusThreadManager::GetSessionBus() {
  return session_bus_.get();
}

DdeVMCompositingClient* DBusThreadManager::GetDdeVMCompositingClient() {
  return clients_browser_ ? clients_browser_->dde_vm_compositing_client_.get()
                          : nullptr;
}

DdeAppearanceThemeClient* DBusThreadManager::GetDdeAppearanceThemeClient() {
  return clients_browser_ ? clients_browser_->dde_appearance_theme_client_.get()
                          : nullptr;
}

DdeMimeClient* DBusThreadManager::GetDdeMimeClient() {
  return clients_browser_ ? clients_browser_->dde_mime_client_.get()
                          : nullptr;
}

DdeManualClient* DBusThreadManager::GetDdeManualClient() {
  return clients_browser_ ? clients_browser_->dde_manual_client_.get()
                          : nullptr;
}

DdePasswordAuthClient * DBusThreadManager::GetDdePasswordAuthClient() {
  return clients_browser_ ? clients_browser_->dde_password_auth_client_.get()
                          : nullptr;
}

void DBusThreadManager::InitializeClients() {
  // Some clients call DBusThreadManager::Get() during initialization.
  DCHECK(g_dbus_thread_manager);

  if (clients_browser_) {
    clients_browser_->InitializeUosSession(GetSessionBus());
  }
}

//  static
void DBusThreadManager::Initialize() {
  // If we initialize DBusThreadManager twice we may also be shutting it down
  // early; do not allow that.
  CHECK(!g_dbus_thread_manager);

  g_dbus_thread_manager = new DBusThreadManager();
  g_dbus_thread_manager->InitializeClients();
}

// static
bool DBusThreadManager::IsInitialized() {
  return !!g_dbus_thread_manager;
}

// static
void DBusThreadManager::Shutdown() {
  // Ensure that we only shutdown DBusThreadManager once.
  CHECK(g_dbus_thread_manager);

  DBusThreadManager* dbus_thread_manager = g_dbus_thread_manager;
  g_dbus_thread_manager = nullptr;
  delete dbus_thread_manager;
  VLOG(1) << "DBusThreadManager Shutdown completed";
}

// static
DBusThreadManager* DBusThreadManager::Get() {
  CHECK(g_dbus_thread_manager)
      << "DBusThreadManager::Get() called before Initialize()";
  return g_dbus_thread_manager;
}

}  // namespace uos
}  // namespace dbus