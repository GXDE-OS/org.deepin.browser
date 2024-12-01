// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DATABASE_CLIENTS_BROWSER_H_
#define UOS_DATABASE_CLIENTS_BROWSER_H_

#include <memory>

#include "base/macros.h"

namespace uos {
namespace database {

class RiskyUrlsDatabase;

class DatabaseClientsBrowser {
 public:
  explicit DatabaseClientsBrowser();
  ~DatabaseClientsBrowser();

  void InitializeUosSession();

  std::unique_ptr<RiskyUrlsDatabase> risk_urls_db_;

 private:
  friend class DatabaseThreadManager;

  DISALLOW_COPY_AND_ASSIGN(DatabaseClientsBrowser);
};

}  // namespace database
} // namespace uos

#endif  // UOS_DATABASE_CLIENTS_BROWSER_H_
