// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview 'settings-driver_manage-list' is a component for showing a
 * list of search engines.
 */
Polymer({
  is: 'settings-driver-manage-list',

  properties: {
    /** @type {!Array<!SearchEngine>} */
    driver: Array,

    /**
     * The scroll target that this list should use.
     * @type {?HTMLElement}
     */
    scrollTarget: Object,

    /** Used to fix scrolling glitch when list is not top most element. */
    scrollOffset: Number,

    /** @private {Object}*/
    lastFocused_: Object,

    /** @private */
    listBlurred_: Boolean,

    fixedHeight: {
      type: Boolean,
      value: false,
      reflectToAttribute: true,
    },
  },
  // ready(){
  //   this.driver = [
  //     {
  //       canBeEdited: true,
  //       canBeRemoved: true,
  //       displayName: "asds",
  //       id: 1,
  //       modelIndex: 0,
  //       name: "asds",
  //       url: "/home/charles/Desktop/libmkskf.so",
  //     },
  //     {
  //       canBeEdited: true,
  //       canBeRemoved: true,
  //       displayName: "asds",
  //       id: 2,
  //       modelIndex: 1,
  //       name: "asds",
  //       url: "/home/charles/Desktop/libmkskf.so",
  //     },
  //     {
  //       canBeEdited: true,
  //       canBeRemoved: true,
  //       displayName: "asds",
  //       id: 3,
  //       modelIndex: 2,
  //       name: "asds",
  //       url: "/home/charles/Desktop/libmkskf.so",
  //     }
  //   ]
  // },
});
