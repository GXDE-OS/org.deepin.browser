// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview 'cr-button' is a button which displays slotted elements. It can
 * be interacted with like a normal button using click as well as space and
 * enter to effectively click the button and fire a 'click' event.
 */
Polymer({
  is: 'cr-button',

  behaviors: [
    Polymer.PaperRippleBehavior,
  ],

  properties: {
    disabled: {
      type: Boolean,
      value: false,
      reflectToAttribute: true,
      observer: 'disabledChanged_',
    },

    /**
     * Use this property in order to configure the "tabindex" attribute.
     */
    customTabIndex: {
      type: Number,
      observer: 'applyTabIndex_',
    },

    /**
     * Flag used for formatting ripples on circle shaped cr-buttons.
     * @private
     */
    circleRipple: {
      type: Boolean,
      value: false,
    },
  },

  hostAttributes: {
    'aria-disabled': 'false',
    role: 'button',
    tabindex: 0,
  },

  listeners: {
    click: 'onClick_',
    keydown: 'onKeyDown_',
    keyup: 'onKeyUp_',
    // pointerdown: 'onPointerDown_',
    tap: 'onTap_',
  },

  /** @private {Set<number>} */
  timeoutIds_: null,

  /** @override */
  ready() {
    cr.ui.FocusOutlineManager.forDocument(document);
    this.timeoutIds_ = new Set();
  },

  /** @override */
  detached() {
    this.timeoutIds_.forEach(clearTimeout);
    this.timeoutIds_.clear();
  },

  /**
   * @param {!Function} fn
   * @param {number=} delay
   * @private
   */
  setTimeout_(fn, delay) {
    if (!this.isConnected) {
      return;
    }
    const id = setTimeout(() => {
      this.timeoutIds_.delete(id);
      fn();
    }, delay);
    this.timeoutIds_.add(id);
  },

  /**
   * @param {boolean} newValue
   * @param {boolean|undefined} oldValue
   * @private
   */
  disabledChanged_(newValue, oldValue) {
    if (!newValue && oldValue === undefined) {
      return;
    }
    if (this.disabled) {
      this.blur();
    }
    this.setAttribute('aria-disabled', Boolean(this.disabled));
    this.applyTabIndex_();
  },

  /**
   * Updates the tabindex HTML attribute to the actual value.
   * @private
   */
  applyTabIndex_() {
    let value = this.customTabIndex;
    if (value === undefined) {
      value = this.disabled ? -1 : 0;
    }
    this.setAttribute('tabindex', value);
  },

  /**
   * @param {!Event} e
   * @private
   */
  onClick_(e) {
    if (this.disabled) {
      e.stopImmediatePropagation();
    }
  },

  /**
   * @param {!KeyboardEvent} e
   * @private
   */
  onKeyDown_(e) {
    if (e.key !== ' ' && e.key !== 'Enter') {
      return;
    }

    e.preventDefault();
    e.stopPropagation();

    if (e.repeat) {
      return;
    }

    this.getRipple().uiDownAction();
    if (e.key === 'Enter') {
      this.click();
      // Delay was chosen manually as a good time period for the ripple to be
      // visible.
      this.setTimeout_(() => this.getRipple().uiUpAction(), 100);
    }
  },

  /**
   * @param {!KeyboardEvent} e
   * @private
   */
  onKeyUp_(e) {
    if (e.key !== ' ' && e.key !== 'Enter') {
      return;
    }

    e.preventDefault();
    e.stopPropagation();

    if (e.key === ' ') {
      this.click();
      this.getRipple().uiUpAction();
    }
  },
  // fix bug: https://pms.uniontech.com/zentao/bug-view-78887.html 去除长按动画效果
  // /** @private */
  // onPointerDown_() {
  //   this.ensureRipple();
  // },

  /**
   * Need to handle tap events to enable tap events for where they are still
   * used with |button.addEventListener('tap', handler)|.
   * TODO(crbug.com/812035): Remove function and listener after Chrome OS no
   *     longer uses tap event at least with addEventListener().
   * @private
   */
  onTap_() {},

  /**
   * Customize the element's ripple. Overriding the '_createRipple' function
   * from PaperRippleBehavior.
   * @return {PaperRippleElement}
   */
  _createRipple() {
    const ripple = Polymer.PaperRippleBehavior._createRipple();

    if (this.circleRipple) {
      ripple.setAttribute('center', '');
      ripple.classList.add('circle');
    }

    return ripple;
  },
});
