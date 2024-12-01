// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DATABASE_THREAD_MANAGER_H_
#define UOS_DATABASE_THREAD_MANAGER_H_

#include <memory>
#include <string>

#include "base/macros.h"

namespace base {
class Thread;
}  // namespace base

namespace uos {
namespace database {

class RiskyUrlsDatabase;
class DatabaseClientsBrowser;

class DatabaseThreadManager {
 public:  
  // Returns true if DatabaseThreadManager has been initialized. Call this to
  // avoid initializing + shutting down DatabaseThreadManager more than once.
  static bool IsInitialized();

  // Destroys the global instance.
  static void Shutdown();

  // Gets the global instance. Initialize() must be called first.
  static DatabaseThreadManager* Get();
  
  RiskyUrlsDatabase * GetRiskyUrlsDatabase();

  // Initializes all currently stored DBusClients with the system bus and
  // performs additional setup.
  static void Initialize();

 private:
   explicit DatabaseThreadManager();
  ~DatabaseThreadManager();

  void InitializeClients();

  std::unique_ptr<base::Thread> database_thread_;

  // Clients used only by the browser process. Null in other processes.
  std::unique_ptr<DatabaseClientsBrowser> clients_browser_;
};

}  // namespace database
}  // namespace uos

#endif  // UOS_DATABASE_THREAD_MANAGER_H_