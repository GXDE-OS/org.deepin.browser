// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/child/npapi/webplugin_delegate_impl.h"

#include <iostream>

#include "content/child/npapi/plugin_instance.h"
#include "content/common/cursors/webcursor.h"
//#include "content/public/common/cursor_info.h"

using blink::WebInputEvent;

namespace content {

WebPluginDelegateImpl::WebPluginDelegateImpl(WebPlugin* plugin,
                                             PluginInstance* instance) {
}

WebPluginDelegateImpl::~WebPluginDelegateImpl() {
}

bool WebPluginDelegateImpl::PlatformInitialize() {
  return true;
}

void WebPluginDelegateImpl::PlatformDestroyInstance() {
  // Nothing to do here.
}

void WebPluginDelegateImpl::Paint(cc::PaintCanvas* canvas, const gfx::Rect& rect) {
}

bool WebPluginDelegateImpl::WindowedCreatePlugin() {
  return true;
}

void WebPluginDelegateImpl::WindowedDestroyWindow() {
}

bool WebPluginDelegateImpl::WindowedReposition(
    const gfx::Rect& window_rect,
    const gfx::Rect& clip_rect) {
  return true;
}

void WebPluginDelegateImpl::WindowedSetWindow() {
}

void WebPluginDelegateImpl::WindowlessUpdateGeometry(
    const gfx::Rect& window_rect,
    const gfx::Rect& clip_rect) {
}

void WebPluginDelegateImpl::WindowlessPaint(gfx::NativeDrawingContext context,
                                            const gfx::Rect& damage_rect) {
}

bool WebPluginDelegateImpl::PlatformSetPluginHasFocus(bool focused) {
  return true;
}

bool WebPluginDelegateImpl::PlatformHandleInputEvent(
    const WebInputEvent& event, ui::Cursor* cursor_info) {
  return false;
}

}  // namespace content
