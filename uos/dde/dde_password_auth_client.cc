// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "uos/dde/dde_password_auth_client.h"

#include "dbus/bus.h"
#include "dbus/message.h"
#include "dbus/object_proxy.h"
#include "dbus/property.h"
#include "uos/dde/dde_constants.h"
#include "uos/dbus_clients_browser.h"
namespace dbus {

namespace uos {

class DdePasswordAuthClientImpl : public DdePasswordAuthClient {
 public:
  DdePasswordAuthClientImpl() {}
  ~DdePasswordAuthClientImpl() override = default;

  bool browserCheckAuthorization() override {
    Bus::Options options;
    options.bus_type = Bus::BusType::SYSTEM;
    options.connection_type = Bus::ConnectionType::PRIVATE;
    options.address = DBusClientsBrowser::GetUOSBusAddress();
    scoped_refptr<Bus> bus = new Bus(options);
    
    ObjectProxy* object_proxy = bus->GetObjectProxy(kPolkitServiceName, ObjectPath(kPolkitServicePath));
    MethodCall method_call(kPolkitServiceInterface, kPolkitCheckAuthorization);
    MessageWriter writer(&method_call);

    bool is_authorized = false;

    {
      MessageWriter struct_writer(nullptr);
      writer.OpenStruct(&struct_writer);
      struct_writer.AppendString("unix-process");
      {
        MessageWriter dict_array_writer(nullptr);
        struct_writer.OpenArray("{sv}", &dict_array_writer);
        {
          {
            MessageWriter dict_entry_writer(nullptr);
            dict_array_writer.OpenDictEntry(&dict_entry_writer);
            dict_entry_writer.AppendString("pid");
            {
              MessageWriter variant_writer(nullptr);
              dict_entry_writer.OpenVariant("u", &variant_writer);
              variant_writer.AppendUint32((uint32_t)getpid());
              dict_entry_writer.CloseContainer(&variant_writer);
            }
            dict_array_writer.CloseContainer(&dict_entry_writer);
          }

          {
            MessageWriter dict_entry_writer(nullptr);
            dict_array_writer.OpenDictEntry(&dict_entry_writer);
            dict_entry_writer.AppendString("start-time");
            {
              MessageWriter variant_writer(nullptr);
              dict_entry_writer.OpenVariant("t", &variant_writer);
              variant_writer.AppendUint64(0);
              dict_entry_writer.CloseContainer(&variant_writer);
            }
            dict_array_writer.CloseContainer(&dict_entry_writer);
          }
        }
        struct_writer.CloseContainer(&dict_array_writer);
      }
      writer.CloseContainer(&struct_writer);
    }
    
    writer.AppendString("com.deepin.pkexec.deepin-password-auth");
    {
      MessageWriter dict_array_writer(nullptr);
      writer.OpenArray("{ss}", &dict_array_writer);
      writer.CloseContainer(&dict_array_writer);
    }
    writer.AppendUint32(1);
    writer.AppendString("");

    std::unique_ptr<Response> response(object_proxy->CallMethodAndBlock(&method_call, 100000000));
    if (response.get() != nullptr) {  // Success.
      MessageReader read(response.get());
      MessageReader struct_reader(nullptr);
      if (read.PopStruct(&struct_reader) && struct_reader.PopBool(&is_authorized)) {
        LOG(INFO) << "Browser password auth : " << is_authorized;
      }
    }
    bus->ShutdownAndBlock();

    return is_authorized;
  }

protected:
  void Init(Bus* bus) override {}

private:
  DISALLOW_COPY_AND_ASSIGN(DdePasswordAuthClientImpl);
};

DdePasswordAuthClient::DdePasswordAuthClient() = default;
DdePasswordAuthClient::~DdePasswordAuthClient() = default;

std::unique_ptr<DdePasswordAuthClient> DdePasswordAuthClient::Create() {
  return std::make_unique<DdePasswordAuthClientImpl>();
}

}   //  namespace uos

}   //  namespace dbus