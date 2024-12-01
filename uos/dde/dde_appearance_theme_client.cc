// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "uos/dde/dde_appearance_theme_client.h"

#include <gio/gio.h>

#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "dbus/bus.h"
#include "dbus/message.h"
#include "dbus/object_proxy.h"
#include "dbus/property.h"
#include "ui/base/glib/glib_signal.h"
#include "ui/native_theme/native_theme.h"
#include "uos/dde/dde_constants.h"

namespace dbus {

namespace uos {

const char kDeepinSchema[] = "com.deepin.xsettings";

const char kThemeNameKey[] = "theme-name";
const char kThemeNameChangedSignal[] = "changed::theme-name";

////////////////////////////////////////////////////////////////////////////////
class DdeAppearanceThemeClientImpl : public DdeAppearanceThemeClient {
 public:
  DdeAppearanceThemeClientImpl() = default;
  ~DdeAppearanceThemeClientImpl() override = default;
 
  void updateAppThemeColor(const std::string& themeValue) override {
    bool isUseDarkColor = false;
    if(themeValue == kAppearanceGtkThemeDark) {   //  浏览器应用主题是深色
      isUseDarkColor = true;
    } else if(themeValue == kAppearanceGtkThemeLight) {
      
    } else {
      if(ddeGtkTheme == kAppearanceGtkThemeDark) {  // 浏览器应用主题是跟随系统, 系统主题是深色
        isUseDarkColor = true;
      }
    }
    
    ui::NativeTheme::GetInstanceForNativeUi()->set_use_dark_colors(isUseDarkColor);
    ui::NativeTheme::GetInstanceForNativeUi()->NotifyObservers();
    ui::NativeTheme::GetInstanceForWeb()->NotifyObservers();
  }

  void setAppTheme(const std::string& sTheme) override {
    browserGtkTheme = sTheme;

    saveBrowserTheme();
  }

  std::string getAppCurrentTheme() override {
    return browserGtkTheme;
  }

  bool isUseDarkColor() override {
    if(browserGtkTheme == kAppearanceGtkThemeDark){   //  浏览器自己是深色主题
      return true;
    }

    if(browserGtkTheme == kAppearanceGtkThemeSystem){ //  浏览器自己主题是跟随系统, 
      if(ddeGtkTheme == kAppearanceGtkThemeDark){ //  系统当前是深色主题
         return true;
      }
    }

    return false;
  }

 protected:
  void Init(Bus* bus) override {
    InitBrowserTheme();

    InitSystemTheme();

    updateAppThemeColor(browserGtkTheme);
  }

 private:
  CHROMEG_CALLBACK_1(DdeAppearanceThemeClientImpl,
                     void,
                     OnThemeNameChanged,
                     GSettings*,
                     const gchar*);
                     
  //  浏览器自己主题初始化
  void InitBrowserTheme() {
    base::FilePath home_dir = base::GetHomeDir();

    base::FilePath theme_file = home_dir.Append(".config/browser/theme.conf");
    
    //  浏览器第一次运行,没有该配置文件, 则保存浏览器应用主题为 系统跟随
    if( !base::PathExists(theme_file) ) {
      base::WriteFile(theme_file, kAppearanceGtkThemeSystem, sizeof(kAppearanceGtkThemeSystem));
    } else {    
      char buffer[1024] = {0};
  
      int read_size = sizeof(buffer);
      int64_t actual_size;
      if (base::GetFileSize(theme_file, &actual_size) && actual_size < read_size)
        read_size = actual_size;
      
      base::ReadFile(theme_file, buffer, read_size);
    
      browserGtkTheme = std::string(buffer);
    }
  }

  //  浏览器保存自己主题
  void saveBrowserTheme() {
    base::FilePath home_dir = base::GetHomeDir();

    base::FilePath theme_file = home_dir.Append(".config/browser/theme.conf");
    
    base::WriteFile(theme_file, browserGtkTheme.c_str(), browserGtkTheme.length());
  }

  void InitSystemTheme() {
    GSettingsSchema* deepin_schema = g_settings_schema_source_lookup(
      g_settings_schema_source_get_default(), kDeepinSchema, FALSE);
    if (deepin_schema) {
      if(g_settings_schema_has_key(deepin_schema, kThemeNameKey)) {
        theme_settings_ = g_settings_new(kDeepinSchema);
        signal_theme_id_ =
        g_signal_connect(theme_settings_, kThemeNameChangedSignal,
                         G_CALLBACK(OnThemeNameChangedThunk), this);

        gchar* temp_theme = g_settings_get_string(theme_settings_, kThemeNameKey);
        if (!temp_theme)
          return;

        ddeGtkTheme = temp_theme;

        g_free(temp_theme);
      }
    }
  }

  GSettings* theme_settings_ = nullptr;
  gulong signal_theme_id_;

  //  用于 接收dbus 的信号
  // ObjectProxy* proxy_ = nullptr;

  //  浏览器窗口主题
  std::string browserGtkTheme = kAppearanceGtkThemeSystem;

  //  系统窗口主题
  std::string ddeGtkTheme = kAppearanceGtkThemeLight;

  // Note: This should remain the last member so it'll be destroyed and
  // invalidate its weak pointers before any other members are destroyed.
  base::WeakPtrFactory<DdeAppearanceThemeClientImpl> weak_ptr_factory_{this};

  DISALLOW_COPY_AND_ASSIGN(DdeAppearanceThemeClientImpl);
};

void DdeAppearanceThemeClientImpl::OnThemeNameChanged(GSettings* settings, const gchar* key) {
  gchar* temp_theme = g_settings_get_string(settings, kThemeNameKey);
  if (!temp_theme)
    return;

  ddeGtkTheme = temp_theme;
  LOG(INFO) << "OnThemeNameChanged   " << temp_theme;

  g_free(temp_theme);

  if(browserGtkTheme == kAppearanceGtkThemeSystem) {  //  浏览器应用的主题是跟随系统
    updateAppThemeColor(browserGtkTheme);
  }
  //hwb change all chrome::
}


// DdeAppearanceThemeClient
DdeAppearanceThemeClient::DdeAppearanceThemeClient() = default;
DdeAppearanceThemeClient::~DdeAppearanceThemeClient() = default;

// Creates an instance of DdeAppearanceClient.
std::unique_ptr<DdeAppearanceThemeClient> DdeAppearanceThemeClient::Create() {
  return std::make_unique<DdeAppearanceThemeClientImpl>();
}

}   //  namespace uos

}   //  namespace dbus