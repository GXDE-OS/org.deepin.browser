// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview
 * 'settings-driver-page' is the settings page containing driver settings.
 */
Polymer({
  is: 'settings-driver-page',

  properties: {
    prefs: Object,
  },

  /** @override */
  created() {
    console.log("created");
  },

  /** @override */
  ready() {
    console.log("ready");
  },

  /** @private */
  onManageSearchEnginesTap_() {
    settings.Router.getInstance().navigateTo(settings.routes.DRIVER_MANAGE);
  },
});
