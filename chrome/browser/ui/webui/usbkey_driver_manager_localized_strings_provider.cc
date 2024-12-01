// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef OPENSSL_NO_GMTLS
#include "chrome/browser/ui/webui/usbkey_driver_manager_localized_strings_provider.h"

#include "build/build_config.h"
#include "chrome/browser/ui/webui/webui_util.h"
#include "chrome/grit/generated_resources.h"
#include "components/strings/grit/components_strings.h"
#include "content/public/browser/web_ui_data_source.h"
#include "ui/base/webui/web_ui_util.h"

namespace usbkeydriver_manager {

void AddLocalizedStrings(content::WebUIDataSource* html_source) {
  static constexpr webui::LocalizedString kLocalizedStrings[] = {
      {"usbkeydriverManagerTitleInSettingPage",
       IDS_SETTINGS_USBKEYDRIVER_MANAGER_TITLE_IN_SETTING_PAGE},//驱动管理
      {"usbkeydriverManagerLabelInSettingPage",
       IDS_SETTINGS_USBKEYDRIVER_MANAGER_LABEL_IN_SETTING_PAGE},//USB Key驱动管理器
      {"usbkeydriverManagerDriverLoadedLabel",
       IDS_SETTINGS_USBKEYDRIVER_MANAGER_DRIVER_LOADED_LABEL},//浏览器目前已加载的USB Key驱动
      {"usbkeydriverManagerDriverName",
       IDS_SETTINGS_COOKIES_COOKIE_NAME_LABEL},//名称
      {"usbkeydriverManagerDriverPath", 
       IDS_SETTINGS_USBKEYDRIVER_MANAGER_DRIVER_PATH},//驱动路径
      {"usbkeydriverManagerDriverAdd",
       IDS_SETTINGS_USBKEYDRIVER_MANAGER_DRIVER_ADD},//添加
      {"usbkeydriverManagerDriverEdit",
       IDS_SETTINGS_USBKEYDRIVER_MANAGER_DRIVER_EDIT},//编辑
      {"statusRemoved", IDS_DOWNLOAD_FILE_REMOVED},//已删除
      {"usbkeydriverManagerDriverDelete",
       IDS_SETTINGS_USBKEYDRIVER_MANAGER_DRIVER_DELETE},//删除
      {"usbkeydriverManagerAddDriverDialogTitle",
       IDS_SETTINGS_USBKEYDRIVER_MANAGER_ADD_DRIVER_DIALOG_TITLE},//添加驱动路径
      {"usbkeydriverManagerAddDriverDialogCancel",
       IDS_SETTINGS_USBKEYDRIVER_MANAGER_ADD_DRIVER_DIALOG_CANCEL},//取消
      {"usbkeydriverManagerAddDriverDialogOk",
       IDS_SETTINGS_USBKEYDRIVER_MANAGER_ADD_DRIVER_DIALOG_OK},//确定
  };
  AddLocalizedStringsBulk(html_source, kLocalizedStrings);
}

}  // namespace usbkeydriver_manager
#endif //#OPENSSL_NO_GMTLS
