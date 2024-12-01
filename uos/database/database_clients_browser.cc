// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "uos/database/database_clients_browser.h"

#include "base/logging.h"
#include "uos/database/database_thread_manager.h"

#include "uos/database/risky_urls_database.h"

namespace uos {
namespace database {

DatabaseClientsBrowser::DatabaseClientsBrowser() {
  risk_urls_db_ = RiskyUrlsDatabase::Create();
}

DatabaseClientsBrowser::~DatabaseClientsBrowser() {
  //
}

void DatabaseClientsBrowser::InitializeUosSession() {
  DCHECK(DatabaseThreadManager::IsInitialized());

  risk_urls_db_->Init();
}

}  // namespace database
}  // namespace uos
