// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/** @fileoverview Handles interprocess communication for the system page. */

// clang-format on
// #import {addSingletonGetter} from 'chrome://resources/js/cr.m.js';
// #import {loadTimeData} from 'chrome://resources/js/load_time_data.m.js';
// clang-format off

cr.define('settings', function() {
  /** @interface */
  /* #export */ class SystemPageBrowserProxy {
    /** Shows the native system proxy settings. */
    showProxySettings() {}

    /**
     * @return {boolean} Whether hardware acceleration was enabled when the user
     *     started Chrome.
     */
    wasHardwareAccelerationEnabledAtStartup() {}
    wasVideoDecodeAccelerationEnabledAtStartup() {}
    wasNationalsslEnabledAtStartup(){}
  }

  /** @implements {settings.SystemPageBrowserProxy} */
  /* #export */ class SystemPageBrowserProxyImpl {
    /** @override */
    showProxySettings() {
      chrome.send('showProxySettings');
    }

    /** @override */
    wasHardwareAccelerationEnabledAtStartup() {
      return loadTimeData.getBoolean('hardwareAccelerationEnabledAtStartup');
    }

    /** @override */
    wasVideoDecodeAccelerationEnabledAtStartup() {
      return loadTimeData.getBoolean('videoDecodeAccelerationEnabledAtStartup');
    }
    
    wasNationalsslEnabledAtStartup() {
      return loadTimeData.getBoolean('nationalsslEnabledAtStartup');
    }
  }

  cr.addSingletonGetter(SystemPageBrowserProxyImpl);

  // #cr_define_end
  return {
    SystemPageBrowserProxy: SystemPageBrowserProxy,
    SystemPageBrowserProxyImpl: SystemPageBrowserProxyImpl,
  };
});
