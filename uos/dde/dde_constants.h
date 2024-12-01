// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UOS_DDE_DDE_CONSTANTS_H_
#define UOS_DDE_DDE_CONSTANTS_H_

namespace dbus {

    namespace uos {
        constexpr char browserid[] = "org.deepin.browser.desktop";

        constexpr char kUosBusAddress[] = "unix:path=/run/user/1000/bus";

        constexpr char kVMServiceName[] = "com.deepin.wm";
        constexpr char kVMServicePath[] = "/com/deepin/wm";
        constexpr char kVMServiceInterface[] = "com.deepin.wm"; 
        constexpr char kVMcompositingEnabled[] = "compositingEnabled";
        constexpr char kVMcompositingEnabledChanged[] = "compositingEnabledChanged";

        constexpr char kAppearanceServiceName[] = "com.deepin.daemon.Appearance";
        constexpr char kAppearanceServicePath[] = "/com/deepin/daemon/Appearance";
        constexpr char kAppearanceServiceInterface[] = "com.deepin.daemon.Appearance";
        
        constexpr char kAppearanceGtkTheme[] = "GtkTheme";
        constexpr char kAppearanceGtkThemeDark[] = "deepin-dark";       //  深色
        constexpr char kAppearanceGtkThemeLight[] = "deepin";           //  浅色
        constexpr char kAppearanceGtkThemeSystem[] = "deepin-auto";     //  跟随系统

        constexpr char kAppearanceQtActiveColor[] = "QtActiveColor";
        constexpr char kAppearanceChanged[] = "Changed";

        constexpr char kMimeServiceName[] = "com.deepin.daemon.Mime";
        constexpr char kMimeServicePath[] = "/com/deepin/daemon/Mime";
        constexpr char kMimeServiceInterface[] = "com.deepin.daemon.Mime";
        constexpr char kMimeSetDefaultApp[] = "SetDefaultApp";
        constexpr char kMimeGetDefaultApp[] = "GetDefaultApp";

        //manual 
        constexpr char KBrowserName[] = "org.deepin.browser";

        //manual open
        constexpr char kManualOpenServiceName[] = "com.deepin.Manual.Open";
        constexpr char kManualOpenServicePath[] = "/com/deepin/Manual/Open";
        constexpr char kManualOpenServiceInterface[] = "com.deepin.Manual.Open";
        constexpr char KShowManual[] = "ShowManual";

        //manual search
        constexpr char kManualSearchServiceName[] = "com.deepin.Manual.Search";
        constexpr char kManualSearchServicePath[] = "/com/deepin/Manual/Search";
        constexpr char kManualSearchServiceInterface[] = "com.deepin.Manual.Search";
        constexpr char KManualExists[] = "ManualExists";

        //polkit password auth
        constexpr char kPolkitServiceName[] = "org.freedesktop.PolicyKit1";
        constexpr char kPolkitServicePath[] = "/org/freedesktop/PolicyKit1/Authority";
        constexpr char kPolkitServiceInterface[] = "org.freedesktop.PolicyKit1.Authority";
        constexpr char kPolkitCheckAuthorization[] = "CheckAuthorization";
    }   //  namespace uos

}   //  namespace dbus
#endif
