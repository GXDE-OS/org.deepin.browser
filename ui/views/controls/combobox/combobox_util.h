// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UI_VIEWS_CONTROLS_COMBOBOX_COMBOBOX_UTIL_H_
#define UI_VIEWS_CONTROLS_COMBOBOX_COMBOBOX_UTIL_H_

#include "third_party/skia/include/core/SkColor.h"
#include "ui/gfx/geometry/size.h"

// Constants and functions common to combobox-like controls so we can reuse code
// and keep the same visual style.

namespace gfx {
class Canvas;
class Rect;
class ImageSkia;
}  // namespace gfx

namespace views {

// Constants for the size of the combobox arrow.
constexpr gfx::Size ComboboxArrowSize() {
  return gfx::Size(/*width=*/8, /*height=*/4);
}
extern const int kComboboxArrowPaddingWidth;
extern const int kComboboxArrowContainerWidth;

// Paints the arrow for a combobox.
void PaintComboboxArrow(SkColor color,
                        const gfx::Rect& bounds,
                        gfx::Canvas* canvas);

//modify by xiaohuyang, Only used to set the style of the drop-down button of ‘combobox’, 2021/3/6
void PaintComboboxArrow(SkColor color,
                        const gfx::Rect& bounds,
                        gfx::Canvas* canvas,
                        const gfx::ImageSkia icon);

}  // namespace views

#endif  // UI_VIEWS_CONTROLS_COMBOBOX_COMBOBOX_UTIL_H_
