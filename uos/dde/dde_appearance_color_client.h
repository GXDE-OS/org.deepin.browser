// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DDE_DDE_APPEARANCE_COLOR_CLIENT_H_
#define UOS_DDE_DDE_APPEARANCE_COLOR_CLIENT_H_

#include <memory>
#include <string>

#include "base/component_export.h"
#include "base/macros.h"
#include "uos/dbus_client.h"

namespace dbus {

namespace uos {

// DdeApparanceClient is used to dde appearance connection with the
// appearance daemon in uos.
class COMPONENT_EXPORT(UOS_DBUS) DdeAppearanceColorClient : public DBusClient {
 public:
  ~DdeAppearanceColorClient() override;

  // Creates an instance of DdeAppearanceClient.
  static std::unique_ptr<DdeAppearanceColorClient> Create();

 protected:
  // Create() should be used instead.
  DdeAppearanceColorClient();

 private:
  DISALLOW_COPY_AND_ASSIGN(DdeAppearanceColorClient);
};

}  // namespace uos

}  // namespace dbus

#endif  // UOS_DDE_DDE_APPEARANCE_COLOR_CLIENT_H_
