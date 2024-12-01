// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "uos/dde/dde_appearance_color_client.h"

#include <gio/gio.h>

#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "dbus/bus.h"
#include "dbus/message.h"
#include "dbus/object_proxy.h"
#include "dbus/property.h"
#include "ui/native_theme/native_theme.h"
#include "uos/dde/dde_constants.h"
#include "uos/dbus_clients_browser.h"

namespace dbus {

namespace uos {

////////////////////////////////////////////////////////////////////////////////
class DdeAppearanceColorClientImpl : public DdeAppearanceColorClient {
 public:
  DdeAppearanceColorClientImpl() = default;
  ~DdeAppearanceColorClientImpl() override = default;
 
 protected:
  void Init(Bus* bus) override {
    proxy_ = bus->GetObjectProxy(kAppearanceServiceName, ObjectPath(kAppearanceServicePath));

    proxy_->ConnectToSignal(kAppearanceServiceInterface, kAppearanceChanged,
      base::BindRepeating(&DdeAppearanceColorClientImpl::OnChanged,
      weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&DdeAppearanceColorClientImpl::OnSignalConnected,
      weak_ptr_factory_.GetWeakPtr()));

    InitQtActiveColor();  
  }

 private:
  // 系统活动色 初始化
  void InitQtActiveColor(){
    Bus::Options options;
    options.bus_type = Bus::BusType::CUSTOM_ADDRESS;
    options.address = DBusClientsBrowser::GetUOSBusAddress();
    options.connection_type = Bus::ConnectionType::PRIVATE;
    scoped_refptr<Bus> bus = new Bus(options);
    
    ObjectProxy* object_proxy = bus->GetObjectProxy(kAppearanceServiceName, ObjectPath(kAppearanceServicePath));
    MethodCall method_call(kPropertiesInterface, kPropertiesGet);
    MessageWriter writer(&method_call);
    writer.AppendString(kAppearanceServiceInterface);
    writer.AppendString(kAppearanceQtActiveColor);

    std::unique_ptr<dbus::Response> response(object_proxy->CallMethodAndBlock(&method_call, 1000));
    if (response.get() != nullptr) {  // Success.
      MessageReader read(response.get());
      std::string value;
      if(read.PopVariantOfString(&value)){
        ddeQtActiveColor = value;
      }
    }
    bus->ShutdownAndBlock();

    LOG(ERROR) << "InitQtActiveColor   ddeQtActiveColor   "  << ddeQtActiveColor;
  }

  //  系统 bus 信号处理, 此处需要判断应用的主题设置是跟随系统, 还是自定义深浅
  void OnChanged(Signal* signal) {
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

  //  窗口活动色
  std::string ddeQtActiveColor = "";

  // Note: This should remain the last member so it'll be destroyed and
  // invalidate its weak pointers before any other members are destroyed.
  base::WeakPtrFactory<DdeAppearanceColorClientImpl> weak_ptr_factory_{this};

  DISALLOW_COPY_AND_ASSIGN(DdeAppearanceColorClientImpl);
};

// DdeApparanceClient
DdeAppearanceColorClient::DdeAppearanceColorClient() = default;
DdeAppearanceColorClient::~DdeAppearanceColorClient() = default;

// Creates an instance of DdeAppearanceColorClient.
std::unique_ptr<DdeAppearanceColorClient> DdeAppearanceColorClient::Create() {
  return std::make_unique<DdeAppearanceColorClientImpl>();
}

}   //  namespace uos

}   //  namespace dbus