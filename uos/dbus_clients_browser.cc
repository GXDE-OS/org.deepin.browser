// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "uos/dbus_clients_browser.h"

#include "base/base_paths.h"
#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "uos/dbus_thread_manager.h"
#include "uos/dde/dde_appearance_theme_client.h"
#include "uos/dde/dde_mime_client.h"
#include "uos/dde/dde_vm_compositing_client.h"
#include "uos/dde/dde_password_auth_client.h"
#include "uos/dde/dde_help_client.h"

namespace dbus {

namespace uos {

DBusClientsBrowser::DBusClientsBrowser() {
  // TODO(hashimoto): Use CREATE_DBUS_CLIENT for all clients after removing
  // DBusClientImplementationType and converting all Create() methods to return
  // std::unique_ptr. crbug.com/952745  
  dde_appearance_theme_client_ = DdeAppearanceThemeClient::Create();
  dde_vm_compositing_client_ = DdeVMCompositingClient::Create(); 
  dde_mime_client_ = DdeMimeClient::Create();
  dde_manual_client_ = DdeManualClient::Create();
  dde_password_auth_client_ = DdePasswordAuthClient::Create();
}

DBusClientsBrowser::~DBusClientsBrowser() = default;

void DBusClientsBrowser::InitializeUosSession(Bus* session_bus) {
  DCHECK(DBusThreadManager::IsInitialized());

  dde_appearance_theme_client_->Init(session_bus);
  dde_vm_compositing_client_->Init(session_bus);
  dde_mime_client_->Init(session_bus);
  dde_manual_client_->Init(session_bus);
  dde_password_auth_client_->Init(session_bus);
}

std::string DBusClientsBrowser::GetUOSBusAddress() {
  auto uid = getuid();
  std::string ret = "unix:path=/run/user/" + std::to_string(uid);
  ret += "/bus";
  return ret;
}

}  // namespace uos

}  // namespace dbus
