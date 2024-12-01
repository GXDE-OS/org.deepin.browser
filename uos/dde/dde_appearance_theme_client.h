// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DDE_DDE_APPEARANCE_THEME_CLIENT_H_
#define UOS_DDE_DDE_APPEARANCE_THEME_CLIENT_H_

#include <memory>
#include <string>

#include "base/component_export.h"
#include "base/macros.h"
#include "uos/dbus_client.h"

namespace dbus {

namespace uos {

// DdeAppearanceThemeClient is used to dde appearance theme connection with the
// appearance daemon in uos.
class COMPONENT_EXPORT(UOS_DBUS) DdeAppearanceThemeClient : public DBusClient {
 public:
  ~DdeAppearanceThemeClient() override;

  // Creates an instance of DdeAppearanceThemeClient.
  static std::unique_ptr<DdeAppearanceThemeClient> Create();

  //  实际调用主题更新
  virtual void updateAppThemeColor(const std::string& themeValue) = 0;

  //  获取当前的主题是否是深色, true为深色, false为浅色
  virtual bool isUseDarkColor() = 0;

  //  浏览器初始化设置浏览器自己使用的主题
  virtual void setAppTheme(const std::string& sTheme) = 0;

  //  浏览器初始化,获取当前浏览器自己的主题设置, 用于系统菜单设置check状态
  virtual std::string getAppCurrentTheme() = 0;

 protected:
  // Create() should be used instead.
  DdeAppearanceThemeClient();

 private:
  DISALLOW_COPY_AND_ASSIGN(DdeAppearanceThemeClient);
};

}  // namespace uos

}  // namespace dbus

#endif  // UOS_DDE_DDE_APPEARANCE_THEME_CLIENT_H_
