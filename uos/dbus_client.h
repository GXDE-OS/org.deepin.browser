// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DBUS_CLIENT_H_
#define UOS_DBUS_CLIENT_H_

#include "base/macros.h"

namespace dbus {
class Bus;

namespace uos {

// Interface for all DBus clients handled by DBusThreadManager. It restricts
// access to the Init function to DBusThreadManager only to prevent
// incorrect calls. Stub clients may lift that restriction however.
class DBusClient {
 protected:
  virtual ~DBusClient() {}

  // This function is called by DBusThreadManager. Only in unit tests, which
  // don't use DBusThreadManager, this function can be called through Stub
  // implementations (they change Init's member visibility to public).
  virtual void Init(Bus* bus) = 0;

 private:
  friend class DBusClientsBrowser;

  DISALLOW_ASSIGN(DBusClient);
};

}  // namespace uos

}  // namespace dbus

#endif  // CHROME_DBUS_DBUS_CLIENT_H_
