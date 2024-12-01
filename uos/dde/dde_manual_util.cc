// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dbus/bus.h"
#include "dbus/message.h"
#include "dbus/object_proxy.h"
#include "uos/dde/dde_constants.h"
#include "uos/dde/dde_manual_util.h"

namespace dbus {
namespace uos {

bool IsManualExists() {
  bool exists = false;

  Bus::Options options;
  options.bus_type = Bus::BusType::SESSION;
  options.connection_type = Bus::ConnectionType::PRIVATE;

  scoped_refptr<Bus> bus = new Bus(options);

  ObjectProxy* object_proxy = 
    bus->GetObjectProxy(kManualSearchServiceName, ObjectPath(kManualSearchServicePath));
  
  MethodCall method_call(kManualSearchServiceInterface, KManualExists);
  MessageWriter writer(&method_call);
  writer.AppendString(KBrowserName);

  //同步方式
  std::unique_ptr<Response> response(
    object_proxy->CallMethodAndBlock(&method_call, 1000));

  if (response.get() != nullptr) {  // Success.
    MessageReader read(response.get());
    if (!read.PopBool(&exists)) {
      LOG(ERROR) << "read response failed.";
    } 
  } 
//   LOG(INFO) << ">>>>>> exists " << exists;
  bus->ShutdownAndBlock();
  return exists;
}

void ShowManualResponse(dbus::Response* response) {
  // response is NULL if the method call failed.
  if (!response) {
    LOG(ERROR) << "ShowManual call failed!";
    return;
  }
}

void ShowManual() {
  Bus::Options options;
  options.bus_type = Bus::BusType::SESSION;
  options.connection_type = Bus::ConnectionType::PRIVATE;

  scoped_refptr<Bus> bus = new Bus(options);

  ObjectProxy* object_proxy = 
    bus->GetObjectProxy(kManualOpenServiceName, ObjectPath(kManualOpenServicePath));
  
  MethodCall method_call(kManualOpenServiceInterface, KShowManual);
  MessageWriter writer(&method_call);
  writer.AppendString(KBrowserName);

  //异步方式
  object_proxy->CallMethod(&method_call, 1000,
    base::BindOnce(&ShowManualResponse));

  bus->ShutdownAndBlock();
}



} //namespace uos

} //namespace bus