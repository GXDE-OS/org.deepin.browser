// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview 'settings-driver_manage-page' is the settings page
 * containing search engines settings.
 */
Polymer({
  is: 'settings-driver-manage-page',

  behaviors: [settings.GlobalScrollTargetBehavior, WebUIListenerBehavior],

  properties: {
    /** @type {!Array<!SearchEngine>} */
    drivers: Array,

    /** @type {!Array<!SearchEngine>} */
    extensions: Array,
    prefs: Object,
    /**
     * Needed by GlobalScrollTargetBehavior.
     * @override
     */
    subpageRoute: {
      type: Object,
      value: settings.routes.DRIVER_MANAGE,
    },

    /** Filters out all search engines that do not match. */
    filter: {
      type: String,
      value: '',
    },

    /** @private {HTMLElement} */
    omniboxExtensionlastFocused_: Object,

    /** @private {boolean} */
    omniboxExtensionListBlurred_: Boolean,

    /** @private {?SearchEngine} */
    dialogModel_: {
      type: Object,
      value: null,
    },

    /** @private {?HTMLElement} */
    dialogAnchorElement_: {
      type: Object,
      value: null,
    },

    /** @private */
    showDialog_: {
      type: Boolean,
      value: false,
    },
  },

  listeners: {
    'edit-driver-manage': 'onEditDriverManage_',
    'save-driver-manage': 'onSaveDriverManage_',
  },

  /** @override */
  ready() {
    settings.DriverManageBrowserProxyImpl.getInstance()
        .getUSBKeyDriversList()
        .then(this.enginesChanged_.bind(this));
  },

  /**
   * @param {?SearchEngine} searchEngine
   * @param {!HTMLElement} anchorElement
   * @private
   */
  openDialog_(searchEngine, anchorElement) {
    this.dialogModel_ = searchEngine;
    this.dialogAnchorElement_ = anchorElement;
    this.showDialog_ = true;
  },

  /** @private */
  onCloseDialog_() {
    this.showDialog_ = false;
    const anchor = /** @type {!HTMLElement} */ (this.dialogAnchorElement_);
    cr.ui.focusWithoutInk(anchor);
    this.dialogModel_ = null;
    this.dialogAnchorElement_ = null;
  },

  /**
   * @param {!CustomEvent<!{
   *     engine: !SearchEngine,
   *     anchorElement: !HTMLElement
   * }>} e
   * @private
   */
  onEditDriverManage_(e) {
    this.prefs.usbkey.default_directory.value = e.detail.engine.path;
    this.openDialog_(e.detail.engine, e.detail.anchorElement);
  },
  /**
   * 
    * @private
    */
   onSaveDriverManage_() {
    settings.DriverManageBrowserProxyImpl.getInstance()
    .getUSBKeyDriversList()
    .then(this.enginesChanged_.bind(this));
   },
  /**
   * @param {!SearchEnginesInfo} searchEnginesInfo
   * @private
   */
  enginesChanged_(searchEnginesInfo) {
    console.log(searchEnginesInfo);
    this.drivers = searchEnginesInfo.driver_info;

    // this.extensions = searchEnginesInfo.extensions;
  },

  /**
   * @param {!Event} e
   * @private
   */
  onAddSearchEngineTap_(e) {
    e.preventDefault();
    this.prefs.usbkey.default_directory.value = "";
    this.openDialog_(
        null, assert(/** @type {HTMLElement} */ (this.$.addSearchEngine)));
  },
});
