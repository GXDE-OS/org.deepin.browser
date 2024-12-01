// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview 'settings-import-data-dialog' is a component for importing
 * bookmarks and other data from other sources.
 */
Polymer({
  is: 'settings-import-data-dialog',

  behaviors: [I18nBehavior, WebUIListenerBehavior, PrefsBehavior],

  properties: {
    /** @private {!Array<!settings.BrowserProfile>} */
    browserProfiles_: Array,
    prefs: Object,
    /** @private {!settings.BrowserProfile} */
    selected_: {
      type: Object,
      observer: 'updateImportDataTypesSelected_',
    },

    /**
     * Whether none of the import data categories is selected.
     * @private
     */
    noImportDataTypeSelected_: {
      type: Boolean,
      value: false,
    },

    /** @private */
    importStatus_: {
      type: String,
      value: settings.ImportDataStatus.INITIAL,
    },
    /** @private */
    selectTxt: {
      type: String,
      value: '',
    },
    /** @private */
    selectedIndex: {
      type: Number,
      value: 0,
    },
    /**
     * Mirroring the enum so that it can be used from HTML bindings.
     * @private
     */
    importStatusEnum_: {
      type: Object,
      value: settings.ImportDataStatus,
    },
    showSelectList: {
      type: Boolean,
      value: false,
    },
  },

  listeners: {
    'settings-boolean-control-change': 'updateImportDataTypesSelected_',
  },

  /** @private {?settings.ImportDataBrowserProxy} */
  browserProxy_: null,
  /** @private */
  showOption: function(e){
    e.stopPropagation();
    this.prefs.showSelect = false;
    let selectList = this.$$('.select-ul'),
        that = this;
    if(selectList.style.display == 'block'){
      selectList.style.display = 'none';
      this.showSelectList = false;
      this.prefs.showSelect = false;
    }else {
      selectList.style.display = 'block';
      this.prefs.showSelect = true;
      this.showSelectList = true;
    }
    Object.defineProperty(this.prefs, 'showSelect', {
      get: function(value) {
      },
      set: function(value) {
        if(that.showSelectList){
          selectList.style.display = 'none';
          that.showSelectList = false;
        }
      }
    });
    
  },
  /**
   * Pass the selection change to the pref value.
   * @private
   */
  selectClick: function(e){
    e.stopPropagation();
    this.showSelectList = false;
    console.log([].indexOf.call(e.target.parentNode.children, e.target));
    let index = [].indexOf.call(e.target.parentNode.children, e.target);
    this.$$('.select-ul').style.display = 'none';
    this.selectedIndex = parseInt(index);
    this.selectTxt = 
        this.getProfileDisplayName_(this.browserProfiles_[index].name,this.browserProfiles_[index].profileName);
    this.selected_ = this.browserProfiles_[index];
  },
  /** @override */
  attached() {
    this.browserProxy_ = settings.ImportDataBrowserProxyImpl.getInstance();
    this.browserProxy_.initializeImportDialog().then(data => {
      this.browserProfiles_ = data;
      this.selected_ = this.browserProfiles_[0];
      this.selectTxt = 
        this.getProfileDisplayName_(this.browserProfiles_[0].name,this.browserProfiles_[0].profileName);
      // Show the dialog only after the browser profiles data is populated
      // to avoid UI flicker.
      this.$.dialog.showModal();
    });

    this.addWebUIListener('import-data-status-changed', importStatus => {
      this.importStatus_ = importStatus;
      if (this.hasImportStatus_(settings.ImportDataStatus.FAILED)) {
        this.closeDialog_();
      }
    });
  },

  /**
   * @param {string} name
   * @param {string} profileName
   * @return {string}
   * @private
   */
  getProfileDisplayName_(name, profileName) {
    return profileName ? `${name} - ${profileName}` : name;
  },

  /** @private */
  updateImportDataTypesSelected_() {
    const checkboxes = this.shadowRoot.querySelectorAll(
        'settings-checkbox[checked]:not([hidden])');
    this.noImportDataTypeSelected_ = checkboxes.length === 0;
  },

  /**
   * @param {!settings.ImportDataStatus} status
   * @return {boolean} Whether |status| is the current status.
   * @private
   */
  hasImportStatus_(status) {
    return this.importStatus_ == status;
  },

  /** @private */
  isImportFromFileSelected_() {
    // The last entry in |browserProfiles_| always refers to dummy profile for
    // importing from a bookmarks file.
    return this.selected_.index == this.browserProfiles_.length - 1;
  },

  /**
   * @return {string}
   * @private
   */
  getActionButtonText_() {
    return this.i18n(
        this.isImportFromFileSelected_() ? 'importChooseFile' : 'importCommit');
  },

  /** @private */
  onActionButtonTap_() {
    const checkboxes = /** @type {!NodeList<!SettingsCheckboxElement>} */ (
        this.shadowRoot.querySelectorAll('settings-checkbox'));
    if (this.isImportFromFileSelected_()) {
      this.browserProxy_.importFromBookmarksFile();
    } else {
      const types = {};
      checkboxes.forEach(checkbox => {
        types[checkbox.pref.key] = checkbox.checked;
      });
      types["import_dialog_search_engine"] = false;
      this.browserProxy_.importData(this.selectedIndex, types);
    }
    checkboxes.forEach(checkbox => checkbox.sendPrefChange());
  },

  /** @private */
  closeDialog_() {
    this.$.dialog.close();
  },

  /**
   * @return {boolean} Whether the import button should be disabled.
   * @private
   */
  shouldDisableImport_() {
    return this.hasImportStatus_(settings.ImportDataStatus.IN_PROGRESS) ||
        this.noImportDataTypeSelected_;
  },
  /**
   * @return {string}
   * @private
   */
  showSelect(dropdownValue,name){
    return dropdownValue == name  ? 'select': '';
  },
});
