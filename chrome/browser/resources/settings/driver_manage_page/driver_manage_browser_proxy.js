// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// clang-format off
// #import {addSingletonGetter, sendWithPromise} from 'chrome://resources/js/cr.m.js';
// clang-format on

/**
 * @fileoverview A helper object used from the "Manage search engines" section
 * to interact with the browser.
 */

/**
 * @typedef {{canBeDefault: boolean,
 *            canBeEdited: boolean,
 *            canBeRemoved: boolean,
 *            default: boolean,
 *            displayName: string,
 *            extension: ({id: string,
 *                         name: string,
 *                         canBeDisabled: boolean,
 *                         icon: string}|undefined),
 *            iconURL: (string|undefined),
 *            id: number,
 *            isOmniboxExtension: boolean,
 *            keyword: string,
 *            modelIndex: number,
 *            name: string,
 *            url: string,
 *            urlLocked: boolean}}
 * @see chrome/browser/ui/webui/settings/search_engine_manager_handler.cc
 */
/* #export */ let DriverManage;

/**
 * @typedef {{
 *   defaults: !Array<!DriverManage>,
 *   others: !Array<!DriverManage>,
 *   extensions: !Array<!DriverManage>
 * }}
 */
/* #export */ let DriverManageInfo;

cr.define('settings', function() {
  /** @interface */
  /* #export */ class DriverManageBrowserProxy {

    /** @param {number} modelIndex */
    removeUSBKeyDriver(modelIndex) {}

    /** @param {number} modelIndex */
    USBKeyDriverEditStarted(modelIndex) {}

    USBKeyDriverEditCancelled() {}

    /**
     * @param {string} name
     * @param {string} path
     */
    USBKeyDriverEditCompleted(id, name, path) {}

    USBKeyDriverSelectLocation(){}

    /** @return {!Promise<!DriverManageInfo>} */
    getUSBKeyDriversList() {}

    /**
     * @param {string} name
     * @param {string} path
     * @return {!Promise<boolean>}
     */
    validateUSBKeyDriverInput(name, path) {}
  }

  /**
   * @implements {settings.DriverManageBrowserProxy}
   */
  /* #export */ class DriverManageBrowserProxyImpl {

    /** @override */
    removeUSBKeyDriver(id) {
      chrome.send('removeUSBKeyDriver', [id]);
    }

    /** @override */
    USBKeyDriverEditStarted(id) {
      chrome.send('USBKeyDriverEditStarted', [id]);
    }

    /** @override */
    USBKeyDriverEditCancelled() {
      chrome.send('USBKeyDriverEditCancelled');
    }

    /** @override */
    USBKeyDriverEditCompleted(id, name, path) {
      chrome.send('USBKeyDriverEditCompleted', [
        id,
        name,
        path,
      ]);
    }


    /** @override */
    USBKeyDriverSelectLocation() {
      chrome.send('USBKeyDriverSelectLocation');
    }
    /** @override */
    getUSBKeyDriversList() {
      return cr.sendWithPromise('getUSBKeyDriversList');
    }

    /** @override */
    validateUSBKeyDriverInput(name, path) {
      return cr.sendWithPromise(
          'validateUSBKeyDriverInput', name, path);
    }
  }

  // The singleton instance_ is replaced with a test version of this wrapper
  // during testing.
  cr.addSingletonGetter(DriverManageBrowserProxyImpl);

  // #cr_define_end
  return {
    DriverManageBrowserProxy: DriverManageBrowserProxy,
    DriverManageBrowserProxyImpl: DriverManageBrowserProxyImpl,
  };
});
