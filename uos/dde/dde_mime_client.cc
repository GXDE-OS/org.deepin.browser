// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "uos/dde/dde_mime_client.h"

#include <vector>

#include "base/json/json_reader.h"
#include "base/optional.h"
#include "base/values.h"
#include "dbus/bus.h"
#include "dbus/message.h"
#include "dbus/object_proxy.h"
#include "dbus/property.h"
#include "uos/dde/dde_constants.h"
#include "uos/dbus_clients_browser.h"

namespace dbus {

namespace uos {

class DdeMimeClientImpl : public DdeMimeClient {
 public:
  DdeMimeClientImpl() = default;
  ~DdeMimeClientImpl() override = default;

  bool SetUosDefaultBrowser() override {
    bool bRes = false;

    //  控制中心采用的 浏览器默认程序
    std::vector<std::string> argv;
    argv.push_back("x-scheme-handler/http");
    argv.push_back("x-scheme-handler/ftp");
    argv.push_back("x-scheme-handler/https");
    argv.push_back("text/html");
    argv.push_back("text/xml");
    argv.push_back("text/xhtml_xml");
    argv.push_back("text/xhtml+xml");

    Bus::Options options;
    options.bus_type = Bus::BusType::CUSTOM_ADDRESS;
    options.address = DBusClientsBrowser::GetUOSBusAddress();
    options.connection_type = Bus::ConnectionType::PRIVATE;
    scoped_refptr<Bus> bus = new Bus(options);
    
    ObjectProxy* object_proxy = bus->GetObjectProxy(kMimeServiceName, ObjectPath(kMimeServicePath));
    MethodCall method_call(kMimeServiceInterface, kMimeSetDefaultApp);
    MessageWriter writer(&method_call);
    writer.AppendArrayOfStrings(argv);
    writer.AppendString(browserid);

    std::unique_ptr<dbus::Response> response(object_proxy->CallMethodAndBlock(&method_call, 1000));
    if (response.get() != nullptr) {  // Success.
      LOG(ERROR) << "  SetDefaultApp Success";
      bRes = true;
    }
    bus->ShutdownAndBlock();

    return bRes;
  }

  bool IsUosDefaultBrowser() override {
    return isDefaultBrowser;
  }

 protected:
  void Init(Bus* bus) override {
    InitUosDefaultBrowser();
  }
 
 private:
  void InitUosDefaultBrowser() {    
    Bus::Options options;
    options.bus_type = Bus::BusType::CUSTOM_ADDRESS;
    options.address = DBusClientsBrowser::GetUOSBusAddress();
    options.connection_type = Bus::ConnectionType::PRIVATE;
    scoped_refptr<Bus> bus = new Bus(options);
      
    ObjectProxy* object_proxy = bus->GetObjectProxy(kMimeServiceName, ObjectPath(kMimeServicePath));
    MethodCall method_call(kMimeServiceInterface, kMimeGetDefaultApp);
    MessageWriter writer(&method_call);
    writer.AppendString("x-scheme-handler/http");

    std::unique_ptr<dbus::Response> response(object_proxy->CallMethodAndBlock(&method_call, 1000));
    if (response.get() != nullptr) {  // Success.
      MessageReader read(response.get());
      std::string value;
      if(read.PopString(&value)){
        ParseStringDefaultBrowser(value);
      }
    }
    bus->ShutdownAndBlock();
  }

  void ParseStringDefaultBrowser(const std::string& input_) {
    base::Optional<base::Value> dict_val = base::JSONReader::Read(input_);
    if(dict_val && dict_val->is_dict()){
      const std::string* str_val = dict_val->FindStringKey("Id");
      if(str_val){
        isDefaultBrowser = *str_val == browserid;

        LOG(INFO) << "  ParseStringDefaultBrowser isDefaultBrowser = " << isDefaultBrowser;
      }
    }
  }

  bool isDefaultBrowser = false;
};

// DdeMimeClient
DdeMimeClient::DdeMimeClient() = default;
DdeMimeClient::~DdeMimeClient() = default;

// Creates an instance of DdeMimeClient.
std::unique_ptr<DdeMimeClient> DdeMimeClient::Create() {
  return std::make_unique<DdeMimeClientImpl>();
}

}  // namespace uos

}  // namespace dbus
