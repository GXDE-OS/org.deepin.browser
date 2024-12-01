// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview 'settings-driver-manage-entry' is a component for showing a
 * search engine with its name, domain and query URL.
 */
Polymer({
  is: 'settings-driver-manage-entry',

  behaviors: [cr.ui.FocusRowBehavior],

  properties: {
    /** @type {!SearchEngine} */
    engine: Object,
    removed: String,
  },

  /** @private {settings.SearchEnginesBrowserProxy} */
  browserProxy_: null,

  /** @override */
  created() {
    this.browserProxy_ = settings.DriverManageBrowserProxyImpl.getInstance();
    this.removed =
          loadTimeData.getString('statusRemoved');
  },
  ready(){
    console.log(this.engine);
  },
  /** @private */
  closePopupMenu_() {
    this.$$('cr-action-menu').close();
  },

  /** @private */
  onDeleteTap_() {
    this.browserProxy_.removeUSBKeyDriver(this.engine.id);
    this.fire('save-driver-manage', {});
    this.closePopupMenu_();
  },

  /** @private */
  onDotsTap_() {
    /** @type {!CrActionMenuElement} */ (this.$$('cr-action-menu'))
        .showAt(assert(this.$$('cr-icon-button')), {
          anchorAlignmentY: AnchorAlignment.AFTER_END,
        });
  },

  /**
   * @param {!Event} e
   * @private
   */
  onEditTap_(e) {
    e.preventDefault();
    this.closePopupMenu_();
    this.fire('edit-driver-manage', {
      engine: this.engine,
      anchorElement: assert(this.$$('cr-icon-button')),
    });
  },
});
