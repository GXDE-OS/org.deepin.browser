// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview 'settings-driver-manage-dialog' is a component for adding
 * or editing a search engine entry.
 */

Polymer({
  is: 'settings-driver-manage-dialog',

  behaviors: [WebUIListenerBehavior],

  properties: {
    /**
     * The search engine to be edited. If not populated a new search engine
     * should be added.
     * @type {?SearchEngine}
     */
    model: Object,

    /** @private {string} */
    name: String,
    /** @private {string} */
    id: String,
    // /** @private {string} */
    // // path: String,
    /** @private {string} */
    dialogTitle_: String,

    /** @private {string} */
    actionButtonText_: String,

    /** @private {Object} */
    prefs: {
      type: Object,
      notify: true,
    },
  },
  /** @private {settings.DriverManageBrowserProxy} */
  browserProxy_: null,

  timer: null,
  /**
   * The |modelIndex| to use when a new search engine is added. Must match with
   * kNewSearchEngineIndex constant specified at
   * chrome/browser/ui/webui/settings/search_engines_handler.cc
   * @type {number}
   */
  DEFAULT_MODEL_INDEX: -1,

  /** @override */
  created() {
    this.browserProxy_ = settings.DriverManageBrowserProxyImpl.getInstance();
  },

  /** @override */
  ready() {
    console.log(this.prefs.usbkey.default_directory.value);
    if (this.model) {
      this.dialogTitle_ =
          loadTimeData.getString('usbkeydriverManagerDriverEdit');
      this.actionButtonText_ = loadTimeData.getString('save');

      // If editing an existing search engine, pre-populate the input fields.
      this.name = this.model.name;
      this.id = this.model.id;
    } else {
      this.dialogTitle_ =
          loadTimeData.getString('usbkeydriverManagerDriverAdd');
      this.actionButtonText_ = loadTimeData.getString('add');
      this.id = -1;
    }
    this.addEventListener('cancel', () => {
      this.browserProxy_.USBKeyDriverEditCancelled();
    });
  },

  /** @override */
  attached() {
    this.async(this.updateActionButtonState_.bind(this));
    // this.browserProxy_.USBKeyDriverEditStarted(
    //     this.model ? this.model.modelIndex : this.DEFAULT_MODEL_INDEX);
    this.$.dialog.showModal();
  },

  /** @private */
  cancel_() {
    /** @type {!CrDialogElement} */ (this.$.dialog).cancel();
  },

  /** @private */
  onActionButtonTap_() {
    console.log(this.prefs.usbkey.default_directory.value);
    this.browserProxy_.USBKeyDriverEditCompleted(
      parseInt(this.id), this.name,  this.prefs.usbkey.default_directory.value);
    this.fire('save-driver-manage', {});
    this.$.dialog.close();
  },

  /**
   * @param {!Element} inputElement
   * @private
   */
  validateElement_(inputElement) {
    // If element is empty, disable the action button, but don't show the red
    // invalid message.
    if (inputElement.value == '') {
      inputElement.invalid = false;
      this.updateActionButtonState_();
      return;
    }

    this.browserProxy_
        .validateUSBKeyDriverInput(inputElement.id, inputElement.value)
        .then(isValid => {
          inputElement.invalid = !isValid;
          this.updateActionButtonState_();
        });
  },

  /**
   * @param {!Event} event
   * @private
   */
  validate_(event) {
    const inputElement = /** @type {!Element} */ (event.target);
    this.validateElement_(inputElement);
  },

  /** @private */
  updateActionButtonState_() {
    const allValid = [
      this.$.driver, this.$.queryUrl
    ].every(function(inputElement) {
      return !inputElement.invalid && inputElement.value.length > 0;
    });
    this.$.actionButton.disabled = !allValid;
  },
  /**
   * @private
   */
  /** @private */
  onKeyBrowse_() {
    let that = this;
    clearInterval(this.timer);
    this.browserProxy_.USBKeyDriverSelectLocation();
    console.log(this.prefs.usbkey.default_directory.value);
    let pathUrl = this.prefs.usbkey.default_directory.value;
    this.timer = setInterval(function(){
      console.log(that.prefs.usbkey.default_directory.value);
      if(pathUrl != that.prefs.usbkey.default_directory.value){
        that.validateElement_(that.$.queryUrl);
        clearInterval(that.timer);
      }
    },100);
  },
});
