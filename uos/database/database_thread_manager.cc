// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "uos/database/database_thread_manager.h"
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/message_loop/message_pump_type.h"
#include "base/threading/thread.h"
#include "uos/database/database_clients_browser.h"

namespace uos {
namespace database {

static DatabaseThreadManager * g_database_thread_manager = nullptr;

DatabaseThreadManager::DatabaseThreadManager() {
  clients_browser_.reset(new DatabaseClientsBrowser);
  
    // Create the D-Bus thread.
  base::Thread::Options thread_options;
  thread_options.message_pump_type = base::MessagePumpType::IO;
  database_thread_.reset(new base::Thread("database thread"));
  database_thread_->StartWithOptions(thread_options);
}

DatabaseThreadManager::~DatabaseThreadManager() {
  // Stop the D-Bus thread.
  if (database_thread_)
    database_thread_->Stop();
}

RiskyUrlsDatabase* DatabaseThreadManager::GetRiskyUrlsDatabase() {
  return clients_browser_ ? clients_browser_->risk_urls_db_.get()
                          : nullptr;
}

void DatabaseThreadManager::InitializeClients() {
  // Some clients call DatabaseThreadManager::Get() during initialization.
  DCHECK(g_database_thread_manager);

  if (clients_browser_) {
    clients_browser_->InitializeUosSession();
  }
}

//  static
void DatabaseThreadManager::Initialize() {
  // If we initialize DatabaseThreadManager twice we may also be shutting it down
  // early; do not allow that.
  CHECK(!g_database_thread_manager);

  g_database_thread_manager = new DatabaseThreadManager();
  g_database_thread_manager->InitializeClients();
}

// static
bool DatabaseThreadManager::IsInitialized() {
  return !!g_database_thread_manager;
}

// static
void DatabaseThreadManager::Shutdown() {
  // Ensure that we only shutdown DatabaseThreadManager once.
  CHECK(g_database_thread_manager);

  DatabaseThreadManager* dbus_thread_manager = g_database_thread_manager;
  g_database_thread_manager = nullptr;
  delete dbus_thread_manager;
  VLOG(1) << "DatabaseThreadManager Shutdown completed";
}

// static
DatabaseThreadManager* DatabaseThreadManager::Get() {
  CHECK(g_database_thread_manager)
      << "DatabaseThreadManager::Get() called before Initialize()";
  return g_database_thread_manager;
}

}  // namespace database
}  // namespace uos