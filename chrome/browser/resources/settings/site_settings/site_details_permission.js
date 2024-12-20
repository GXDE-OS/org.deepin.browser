// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview
 * 'site-details-permission' handles showing the state of one permission, such
 * as Geolocation, for a given origin.
 */
Polymer({
  is: 'site-details-permission',

  behaviors: [I18nBehavior, SiteSettingsBehavior, WebUIListenerBehavior],

  properties: {
    /**
     * If this is a sound content setting, then this controls whether it
     * should use "Automatic" instead of "Allow" as the default setting
     * allow label.
     */
    useAutomaticLabel: {type: Boolean, value: false},
    prefs: Object,
    /**
     * The site that this widget is showing details for.
     * @type {RawSiteException}
     */
    site: Object,

    /**
     * The default setting for this permission category.
     * @type {settings.ContentSetting}
     * @private
     */
    defaultSetting_: String,

    label: String,

    icon: String,
    
    selectName: String,
    showSelectList: {
      type: Boolean,
      value: false,
    },
  },

  observers: ['siteChanged_(site)'],

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
    // let index = [].indexOf.call(e.target.parentNode.children, e.target);
    let dataId = e.target.dataset.id;
    this.$$('.select-ul').style.display = 'none';
    this.removeSelect();
    e.target.classList.add('select');
    this.browserProxy.setOriginPermissions(
      this.site.origin, [this.category], dataId);
  },
  removeSelect(){
    this.$$('#default').classList.remove('select');
    this.$$('#allow').classList.remove('select');
    this.$$('#block').classList.remove('select');
    this.$$('#ask').classList.remove('select');
  },
  /** @override */
  attached() {
    this.addWebUIListener(
        'contentSettingCategoryChanged',
        this.onDefaultSettingChanged_.bind(this));
  },

  shouldHideCategory_(category) {
    return !this.getCategoryList().includes(category);
  },

  /**
   * Updates the drop-down value after |site| has changed.
   * @param {!RawSiteException} site The site to display.
   * @private
   */
  siteChanged_(site) {
    this.removeSelect();
    if (site.source == settings.SiteSettingSource.DEFAULT) {
      this.defaultSetting_ = site.setting;
      this.selectName = this.$$('#'+settings.ContentSetting.DEFAULT).innerText;
      this.$$('#'+settings.ContentSetting.DEFAULT).classList.add('select');
    } else {
      // The default setting is unknown, so consult the C++ backend for it.
      this.updateDefaultPermission_(site);
      this.selectName = this.$$('#'+site.setting).innerText;
      this.$$('#'+site.setting).classList.add('select');
    }

    if (this.isNonDefaultAsk_(site.setting, site.source)) {
      assert(
          this.selectName == this.$$('#'+settings.ContentSetting.ASK).innerText,
          this.$$('#'+settings.ContentSetting.ASK).classList.add('select'),
          '\'Ask\' should only show up when it\'s currently selected.');
    }
  },

  /**
   * Updates the default permission setting for this permission category.
   * @param {!RawSiteException} site The site to display.
   * @private
   */
  updateDefaultPermission_(site) {
    this.browserProxy.getDefaultValueForContentType(this.category)
        .then((defaultValue) => {
          this.defaultSetting_ = defaultValue.setting;
        });
  },

  /**
   * Handles the category permission changing for this origin.
   * @param {!settings.ContentSettingsTypes} category The permission category
   *     that has changed default permission.
   * @private
   */
  onDefaultSettingChanged_(category) {
    if (category == this.category) {
      this.updateDefaultPermission_(this.site);
    }
  },
  /**
   * Returns if we should use the custom labels for the sound type.
   * @param {!settings.ContentSettingsTypes} category The permission type.
   * @return {boolean}
   * @private
   */
  useCustomSoundLabels_(category) {
    return category == settings.ContentSettingsTypes.SOUND &&
        loadTimeData.getBoolean('enableAutoplayWhitelistContentSetting');
  },

  /**
   * Updates the string used for this permission category's default setting.
   * @param {!settings.ContentSetting} defaultSetting Value of the default
   *     setting for this permission category.
   * @param {!settings.ContentSettingsTypes} category The permission type.
   * @param {boolean} useAutomaticLabel Whether to use the automatic label
   *     if the default setting value is allow.
   * @return {string}
   * @private
   */
  defaultSettingString_(defaultSetting, category, useAutomaticLabel) {
    if (defaultSetting == undefined || category == undefined ||
        useAutomaticLabel == undefined) {
      return '';
    }

    if (defaultSetting == settings.ContentSetting.ASK ||
        defaultSetting == settings.ContentSetting.IMPORTANT_CONTENT) {
      return this.i18n('siteSettingsActionAskDefault');
    } else if (defaultSetting == settings.ContentSetting.ALLOW) {
      if (this.useCustomSoundLabels_(category) && useAutomaticLabel) {
        return this.i18n('siteSettingsActionAutomaticDefault');
      }
      return this.i18n('siteSettingsActionAllowDefault');
    } else if (defaultSetting == settings.ContentSetting.BLOCK) {
      if (this.useCustomSoundLabels_(category)) {
        return this.i18n('siteSettingsActionMuteDefault');
      }
      return this.i18n('siteSettingsActionBlockDefault');
    }
    assertNotReached(
        `No string for ${this.category}'s default of ${defaultSetting}`);
  },

  /**
   * Updates the string used for this permission category's block setting.
   * @param {!settings.ContentSettingsTypes} category The permission type.
   * @param {string} blockString 'Block' label.
   * @param {string} muteString 'Mute' label.
   * @return {string}
   * @private
   */
  blockSettingString_(category, blockString, muteString) {
    if (this.useCustomSoundLabels_(category)) {
      return muteString;
    }
    return blockString;
  },

  /**
   * Returns true if there's a string to display that provides more information
   * about this permission's setting. Currently, this only gets called when
   * |this.site| is updated.
   * @param {!settings.SiteSettingSource} source The source of the permission.
   * @param {!settings.ContentSettingsTypes} category The permission type.
   * @param {!settings.ContentSetting} setting The permission setting.
   * @return {boolean} Whether the permission will have a source string to
   *     display.
   * @private
   */
  hasPermissionInfoString_(source, category, setting) {
    // This method assumes that an empty string will be returned for categories
    // that have no permission info string.
    return this.permissionInfoString_(
               source, category, setting,
               // Set all permission info string arguments as null. This is OK
               // because there is no need to know what the information string
               // will be, just whether there is one or not.
               null, null, null, null, null, null, null, null, null, null, null,
               null) != '';
  },

  /**
   * Checks if there's a additional information to display, and returns the
   * class name to apply to permissions if so.
   * @param {!settings.SiteSettingSource} source The source of the permission.
   * @param {!settings.ContentSettingsTypes} category The permission type.
   * @param {!settings.ContentSetting} setting The permission setting.
   * @return {string} CSS class applied when there is an additional description
   *     string.
   * @private
   */
  permissionInfoStringClass_(source, category, setting) {
    return this.hasPermissionInfoString_(source, category, setting) ?
        'two-line' :
        '';
  },

  /**
   * Returns true if this permission can be controlled by the user.
   * @param {!settings.SiteSettingSource} source The source of the permission.
   * @return {boolean}
   * @private
   */
  isPermissionUserControlled_(source) {
    return !(
        source == settings.SiteSettingSource.DRM_DISABLED ||
        source == settings.SiteSettingSource.POLICY ||
        source == settings.SiteSettingSource.EXTENSION ||
        source == settings.SiteSettingSource.KILL_SWITCH ||
        source == settings.SiteSettingSource.INSECURE_ORIGIN);
  },

  /**
   * Returns true if the 'allow' option should be shown.
   * @param {!settings.ContentSettingsTypes} category The permission type.
   * @return {boolean}
   * @private
   */
  showAllowedSetting_(category) {
    return !(
        category == settings.ContentSettingsTypes.SERIAL_PORTS ||
        category == settings.ContentSettingsTypes.USB_DEVICES ||
        category == settings.ContentSettingsTypes.BLUETOOTH_SCANNING ||
        category == settings.ContentSettingsTypes.NATIVE_FILE_SYSTEM_WRITE ||
        category == settings.ContentSettingsTypes.HID_DEVICES ||
        category == settings.ContentSettingsTypes.BLUETOOTH_DEVICES);
  },

  /**
   * Returns true if the 'ask' option should be shown.
   * @param {!settings.ContentSettingsTypes} category The permission type.
   * @param {!settings.ContentSetting} setting The setting of the permission.
   * @param {!settings.SiteSettingSource} source The source of the permission.
   * @return {boolean}
   * @private
   */
  showAskSetting_(category, setting, source) {
    // For chooser-based permissions 'ask' takes the place of 'allow'.
    if (category == settings.ContentSettingsTypes.SERIAL_PORTS ||
        category == settings.ContentSettingsTypes.USB_DEVICES ||
        category == settings.ContentSettingsTypes.HID_DEVICES ||
        category == settings.ContentSettingsTypes.BLUETOOTH_DEVICES) {
      return true;
    }

    // For Bluetooth scanning permission and Native File System write permission
    // 'ask' takes the place of 'allow'.
    if (category == settings.ContentSettingsTypes.BLUETOOTH_SCANNING ||
        category == settings.ContentSettingsTypes.NATIVE_FILE_SYSTEM_WRITE) {
      return true;
    }

    return this.isNonDefaultAsk_(setting, source);
  },

  /**
   * Returns true if the permission is set to a non-default 'ask'. Currently,
   * this only gets called when |this.site| is updated.
   * @param {!settings.ContentSetting} setting The setting of the permission.
   * @param {!settings.SiteSettingSource} source The source of the permission.
   * @private
   */
  isNonDefaultAsk_(setting, source) {
    if (setting != settings.ContentSetting.ASK ||
        source == settings.SiteSettingSource.DEFAULT) {
      return false;
    }

    assert(
        source == settings.SiteSettingSource.EXTENSION ||
            source == settings.SiteSettingSource.POLICY ||
            source == settings.SiteSettingSource.PREFERENCE,
        'Only extensions, enterprise policy or preferences can change ' +
            'the setting to ASK.');
    return true;
  },

  /**
   * Updates the information string for the current permission.
   * Currently, this only gets called when |this.site| is updated.
   * @param {!settings.SiteSettingSource} source The source of the permission.
   * @param {!settings.ContentSettingsTypes} category The permission type.
   * @param {!settings.ContentSetting} setting The permission setting.
   * @param {?string} adsBlacklistString The string to show if the site is
   *     blacklisted for showing bad ads.
   * @param {?string} adsBlockString The string to show if ads are blocked, but
   *     the site is not blacklisted.
   * @param {?string} embargoString
   * @param {?string} insecureOriginString
   * @param {?string} killSwitchString
   * @param {?string} extensionAllowString
   * @param {?string} extensionBlockString
   * @param {?string} extensionAskString
   * @param {?string} policyAllowString
   * @param {?string} policyBlockString
   * @param {?string} policyAskString
   * @param {?string} drmDisabledString
   * @return {?string} The permission information string to display in the HTML.
   * @private
   */
  permissionInfoString_(
      source, category, setting, adsBlacklistString, adsBlockString,
      embargoString, insecureOriginString, killSwitchString,
      extensionAllowString, extensionBlockString, extensionAskString,
      policyAllowString, policyBlockString, policyAskString,
      drmDisabledString) {
    if (source == undefined || category == undefined || setting == undefined) {
      return null;
    }

    /** @type {Object<!settings.ContentSetting, ?string>} */
    const extensionStrings = {};
    extensionStrings[settings.ContentSetting.ALLOW] = extensionAllowString;
    extensionStrings[settings.ContentSetting.BLOCK] = extensionBlockString;
    extensionStrings[settings.ContentSetting.ASK] = extensionAskString;

    /** @type {Object<!settings.ContentSetting, ?string>} */
    const policyStrings = {};
    policyStrings[settings.ContentSetting.ALLOW] = policyAllowString;
    policyStrings[settings.ContentSetting.BLOCK] = policyBlockString;
    policyStrings[settings.ContentSetting.ASK] = policyAskString;

    if (source == settings.SiteSettingSource.ADS_FILTER_BLACKLIST) {
      assert(
          settings.ContentSettingsTypes.ADS == category,
          'The ads filter blacklist only applies to Ads.');
      return adsBlacklistString;
    } else if (
        category == settings.ContentSettingsTypes.ADS &&
        setting == settings.ContentSetting.BLOCK) {
      return adsBlockString;
    } else if (source == settings.SiteSettingSource.DRM_DISABLED) {
      assert(
          settings.ContentSetting.BLOCK == setting,
          'If DRM is disabled, Protected Content must be blocked.');
      assert(
          settings.ContentSettingsTypes.PROTECTED_CONTENT == category,
          'The DRM disabled source only applies to Protected Content.');
      if (!drmDisabledString) {
        return null;
      }
      return loadTimeData.sanitizeInnerHtml(loadTimeData.substituteString(
          drmDisabledString,
          settings.routes.SITE_SETTINGS_PROTECTED_CONTENT.getAbsolutePath()));
    } else if (source == settings.SiteSettingSource.EMBARGO) {
      assert(
          settings.ContentSetting.BLOCK == setting,
          'Embargo is only used to block permissions.');
      return embargoString;
    } else if (source == settings.SiteSettingSource.EXTENSION) {
      return extensionStrings[setting];
    } else if (source == settings.SiteSettingSource.INSECURE_ORIGIN) {
      assert(
          settings.ContentSetting.BLOCK == setting,
          'Permissions can only be blocked due to insecure origins.');
      return insecureOriginString;
    } else if (source == settings.SiteSettingSource.KILL_SWITCH) {
      assert(
          settings.ContentSetting.BLOCK == setting,
          'The permissions kill switch can only be used to block permissions.');
      return killSwitchString;
    } else if (source == settings.SiteSettingSource.POLICY) {
      return policyStrings[setting];
    } else if (
        source == settings.SiteSettingSource.DEFAULT ||
        source == settings.SiteSettingSource.PREFERENCE) {
      return '';
    }
    assertNotReached(`No string for ${category} setting source '${source}'`);
  },
});
