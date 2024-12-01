// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DDE_MANUAL_CLIENT_H_
#define DDE_MANUAL_CLIENT_H_

#include <memory>
#include <string>

#include "base/component_export.h"
#include "base/macros.h"

namespace dbus {

namespace uos {

bool IsManualExists();

void ShowManual();

} //namespace uos

} //namespace dbus


#endif //DDE_MANUAL_CLIENT_H_