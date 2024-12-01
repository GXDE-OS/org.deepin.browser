// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "uos/dde/dde_vm_compositing_client.h"

#include "dbus/bus.h"
#include "dbus/message.h"
#include "dbus/object_proxy.h"
#include "dbus/property.h"
#include "uos/dde/dde_constants.h"
#include "uos/dbus_clients_browser.h"
namespace dbus {

namespace uos {
////////////////////////////////////////////////////////////////////////////////
class DdeVMCompositingClientImpl : public DdeVMCompositingClient {
 public:
  DdeVMCompositingClientImpl() {}
  ~DdeVMCompositingClientImpl() override = default;

  bool getCompositingEnabled() override {   
    return ddeCompositingEnabled;
  }

 protected:
  void Init(Bus* bus) override {
    proxy_ = bus->GetObjectProxy(kVMServiceName, ObjectPath(kVMServicePath));
    proxy_->ConnectToSignal(
      kVMServiceInterface, kVMcompositingEnabledChanged,
      base::BindRepeating(&DdeVMCompositingClientImpl::CompositingEnabledChanged,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&DdeVMCompositingClientImpl::OnSignalConnected,
                     weak_ptr_factory_.GetWeakPtr()));

    InitCompositingEnable();
  }

 private:
  // 窗口特效 唯一初始化
  void InitCompositingEnable(){  
    Bus::Options options;
    options.bus_type = Bus::BusType::CUSTOM_ADDRESS;
    options.connection_type = Bus::ConnectionType::PRIVATE;
    options.address = DBusClientsBrowser::GetUOSBusAddress();
    scoped_refptr<Bus> bus = new Bus(options);
    
    ObjectProxy* object_proxy = bus->GetObjectProxy(kVMServiceName, ObjectPath(kVMServicePath));
    MethodCall method_call(kPropertiesInterface, kPropertiesGet);
    MessageWriter writer(&method_call);
    writer.AppendString(kVMServiceInterface);
    writer.AppendString(kVMcompositingEnabled);

    std::unique_ptr<Response> response(object_proxy->CallMethodAndBlock(&method_call, 1000));
    if (response.get() != nullptr) {  // Success.
      MessageReader read(response.get());
      bool value;
      if(read.PopVariantOfBool(&value)){
        ddeCompositingEnabled = value;
      }
    }
    bus->ShutdownAndBlock();

    LOG(INFO) << "InitCompositingEnable   ddeCompositingEnabled   "  << ddeCompositingEnabled;
  }
  
  void CompositingEnabledChanged(Signal* signal) {
    DCHECK(signal);

    MessageReader reader(signal);
    bool value;
    if (!reader.PopBool(&value)) {
      LOG(ERROR) << "Invalid signal: " << signal->ToString();
      return;
    }

    ddeCompositingEnabled = value;
  }

   // Handles the result of signal connection setup.
  void OnSignalConnected(const std::string& interface,
                         const std::string& signal,
                         bool succeeded) {
    LOG_IF(ERROR, !succeeded) << "Connect to " << interface << " " <<
        signal << " failed.";
  }

  //  用于 接收dbus 的信号
  ObjectProxy* proxy_ = nullptr;

  //  窗口特效状态, false 关闭, true 开启
  bool ddeCompositingEnabled = false;

  // Note: This should remain the last member so it'll be destroyed and
  // invalidate its weak pointers before any other members are destroyed.
  base::WeakPtrFactory<DdeVMCompositingClientImpl> weak_ptr_factory_{this};

  DISALLOW_COPY_AND_ASSIGN(DdeVMCompositingClientImpl);
};

// DdeApparanceClient
DdeVMCompositingClient::DdeVMCompositingClient() = default;
DdeVMCompositingClient::~DdeVMCompositingClient() = default;

std::unique_ptr<DdeVMCompositingClient> DdeVMCompositingClient::Create() {
  return std::make_unique<DdeVMCompositingClientImpl>();
}

}   //  namespace uos

}   //  namespace dbus