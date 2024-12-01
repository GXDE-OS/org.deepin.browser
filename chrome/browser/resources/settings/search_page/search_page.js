// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview
 * 'settings-search-page' is the settings page containing search settings.
 */
Polymer({
  is: 'settings-search-page',

  properties: {
    prefs: Object,

    /**
     * List of default search engines available.
     * @private {!Array<!SearchEngine>}
     */
    searchEngines_: {
      type: Array,
      value() {
        return [];
      }
    },
    searchDefaults:{
      type: String,
      value() {
        return '';
      }
    },

    /** @private Filter applied to search engines. */
    searchEnginesFilter_: String,

    /** @type {?Map<string, string>} */
    focusConfig_: Object,
    showSelectList: {
      type: Boolean,
      value: false,
    },
  },
  selectClick: function(e){
    e.stopPropagation();
    this.$$('.select-ul').style.display = 'none';
    this.showSelectList = false;
    let index = [].indexOf.call(e.target.parentNode.children, e.target);
    this.browserProxy_.setDefaultSearchEngine(index);
  },
  /** @private {?settings.SearchEnginesBrowserProxy} */
  browserProxy_: null,

  /** @override */
  created() {
    this.browserProxy_ = settings.SearchEnginesBrowserProxyImpl.getInstance();
  },

  /** @override */
  ready() {
    // Omnibox search engine
    const updateSearchEngines = searchEngines => {
      this.set('searchEngines_', searchEngines.defaults);
      this.set('searchDefaults', setSearchDefaults(searchEngines.defaults));
    };
    this.browserProxy_.getSearchEnginesList().then(updateSearchEngines);
    cr.addWebUIListener('search-engines-changed', updateSearchEngines);
    const setSearchDefaults = (list) => {
      const filterList = list.filter(item => item.default);
      console.log(filterList);
      return filterList[0].name;
    }
    this.focusConfig_ = new Map();
    if (settings.routes.SEARCH_ENGINES) {
      this.focusConfig_.set(
          settings.routes.SEARCH_ENGINES.path, '#enginesSubpageTrigger');
    }
  },

  /** @private */
  onDisableExtension_() {
    this.fire('refresh-pref', 'default_search_provider.enabled');
  },

  /** @private */
  onManageSearchEnginesTap_() {
    settings.Router.getInstance().navigateTo(settings.routes.SEARCH_ENGINES);
  },

  /**
   * @param {!chrome.settingsPrivate.PrefObject} pref
   * @return {boolean}
   * @private
   */
  isDefaultSearchControlledByPolicy_(pref) {
    return pref.controlledBy == chrome.settingsPrivate.ControlledBy.USER_POLICY;
  },

  /**
   * @param {!chrome.settingsPrivate.PrefObject} pref
   * @return {boolean}
   * @private
   */
  isDefaultSearchEngineEnforced_(pref) {
    return pref.enforcement == chrome.settingsPrivate.Enforcement.ENFORCED;
  },
  
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
   * @return {string}
   * @private
   */
  showSelect(dropdownValue,name){
    return dropdownValue == name  ? 'select': '';
  },
});
