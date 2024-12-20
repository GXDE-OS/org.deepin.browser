// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/native_theme/common_theme.h"

#include "base/logging.h"
#include "base/optional.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/gfx/canvas.h"
#include "ui/gfx/color_palette.h"
#include "ui/gfx/color_utils.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/gfx/skia_util.h"
#include "ui/native_theme/overlay_scrollbar_constants_aura.h"

namespace ui {

namespace {

base::Optional<SkColor> GetHighContrastColor(
    NativeTheme::ColorId color_id,
    NativeTheme::ColorScheme color_scheme) {
  switch (color_id) {
    case NativeTheme::kColorId_ButtonUncheckedColor:
    case NativeTheme::kColorId_MenuBorderColor:
    case NativeTheme::kColorId_MenuSeparatorColor:
    case NativeTheme::kColorId_SeparatorColor:
    case NativeTheme::kColorId_UnfocusedBorderColor:
    case NativeTheme::kColorId_TabBottomBorder:
      return color_scheme == NativeTheme::ColorScheme::kDark ? SK_ColorWHITE
                                                             : SK_ColorBLACK;
    case NativeTheme::kColorId_ButtonEnabledColor:
    case NativeTheme::kColorId_FocusedBorderColor:
    case NativeTheme::kColorId_ProminentButtonColor:
      return color_scheme == NativeTheme::ColorScheme::kDark
                 ? gfx::kGoogleBlue100
                 : gfx::kGoogleBlue900;
    default:
      return base::nullopt;
  }
}

base::Optional<SkColor> GetDarkSchemeColor(NativeTheme::ColorId color_id) {
  switch (color_id) {
    // Dialogs
    case NativeTheme::kColorId_WindowBackground:
    case NativeTheme::kColorId_DialogBackground:
    case NativeTheme::kColorId_BubbleBackground:
      return color_utils::AlphaBlend(SK_ColorWHITE, gfx::kGoogleGrey900, 0.04f);
    case NativeTheme::kColorId_DialogForeground:
      return gfx::kGoogleGrey500;
    case NativeTheme::kColorId_BubbleForeground:
      return gfx::kGoogleGrey200;
    case NativeTheme::kColorId_BubbleFooterBackground:
      return SkColorSetRGB(0x32, 0x36, 0x39);

    // FocusableBorder
    case NativeTheme::kColorId_FocusedBorderColor:
      return SkColorSetA(gfx::kGoogleBlue300, 0x4D);
    case NativeTheme::kColorId_UnfocusedBorderColor:
      return gfx::kGoogleGrey800;

    // Button
    case NativeTheme::kColorId_ButtonBorderColor:
      return gfx::kGoogleGrey800;
    case NativeTheme::kColorId_ButtonEnabledColor:
    case NativeTheme::kColorId_ProminentButtonColor:
      return gfx::kGoogleBlue300;
    case NativeTheme::kColorId_ButtonHoverColor:
      return SkColorSetA(SK_ColorBLACK, 0x0A);
    case NativeTheme::kColorId_ButtonInkDropShadowColor:
      return SkColorSetA(SK_ColorBLACK, 0x7F);
    case NativeTheme::kColorId_ButtonInkDropFillColor:
    case NativeTheme::kColorId_ProminentButtonInkDropFillColor:
      return SkColorSetA(SK_ColorWHITE, 0x0A);
    case NativeTheme::kColorId_ProminentButtonInkDropShadowColor:
      return SkColorSetA(gfx::kGoogleBlue300, 0x7F);
    case NativeTheme::kColorId_ProminentButtonHoverColor:
      return SkColorSetA(SK_ColorWHITE, 0x0A);
    case NativeTheme::kColorId_ButtonUncheckedColor:
      return gfx::kGoogleGrey500;
    case NativeTheme::kColorId_TextOnProminentButtonColor:
      return gfx::kGoogleGrey900;
    case NativeTheme::kColorId_PaddedButtonInkDropColor:
      return SK_ColorWHITE;

    // MenuItem
    case NativeTheme::kColorId_HighlightedMenuItemForegroundColor:
    case NativeTheme::kColorId_MenuDropIndicator:
      return gfx::kGoogleGrey200;
    case NativeTheme::kColorId_MenuBorderColor:
    case NativeTheme::kColorId_MenuSeparatorColor:
      return gfx::kGoogleGrey800;
    case NativeTheme::kColorId_HighlightedMenuItemBackgroundColor:
      return SkColorSetRGB(0x32, 0x36, 0x39);
    case NativeTheme::kColorId_MenuItemInitialAlertBackgroundColor:
      return SkColorSetA(gfx::kGoogleBlue300, 0x4D);
    case NativeTheme::kColorId_MenuItemTargetAlertBackgroundColor:
      return SkColorSetA(gfx::kGoogleBlue300, 0x1A);
    case NativeTheme::kColorId_MenuItemMinorTextColor:
      return gfx::kGoogleGrey500;

    // Custom frame view
    case NativeTheme::kColorId_CustomFrameActiveColor:
      return gfx::kGoogleGrey900;
    case NativeTheme::kColorId_CustomFrameInactiveColor:
      return gfx::kGoogleGrey800;

    // Dropdown
    case NativeTheme::kColorId_DropdownBackgroundColor:
      return color_utils::AlphaBlend(SK_ColorWHITE, gfx::kGoogleGrey900, 0.04f);
    case NativeTheme::kColorId_DropdownForegroundColor:
      return gfx::kGoogleGrey200;
    case NativeTheme::kColorId_DropdownSelectedForegroundColor:
      return gfx::kGoogleGrey200;

    // Label
    case NativeTheme::kColorId_LabelEnabledColor:
    case NativeTheme::kColorId_LabelTextSelectionColor:
      return gfx::kGoogleGrey200;
    case NativeTheme::kColorId_LabelSecondaryColor:
      return gfx::kGoogleGrey500;
    case NativeTheme::kColorId_LabelTextSelectionBackgroundFocused:
      return gfx::kGoogleBlue800;

    // Link
    case NativeTheme::kColorId_LinkEnabled:
    case NativeTheme::kColorId_LinkPressed:
      return gfx::kGoogleBlue300;

    // Separator
    case NativeTheme::kColorId_SeparatorColor:
      return gfx::kGoogleGrey800;

    // TabbedPane
    case NativeTheme::kColorId_TabTitleColorActive:
      return gfx::kGoogleBlue300;
    case NativeTheme::kColorId_TabTitleColorInactive:
      return gfx::kGoogleGrey500;
    case NativeTheme::kColorId_TabBottomBorder:
      return gfx::kGoogleGrey800;
    case NativeTheme::kColorId_TabHighlightBackground:
      return gfx::kGoogleGrey800;
    case NativeTheme::kColorId_TabHighlightFocusedBackground:
      return SkColorSetRGB(0x32, 0x36, 0x39);

    // Table
    case NativeTheme::kColorId_TableBackground:
    case NativeTheme::kColorId_TableBackgroundAlternate:
      return color_utils::AlphaBlend(SK_ColorWHITE, gfx::kGoogleGrey900, 0.04f);
    case NativeTheme::kColorId_TableText:
    case NativeTheme::kColorId_TableSelectedText:
    case NativeTheme::kColorId_TableSelectedTextUnfocused:
      return gfx::kGoogleGrey200;

    // Textfield
    case NativeTheme::kColorId_TextfieldDefaultColor:
    case NativeTheme::kColorId_TextfieldSelectionColor:
      return gfx::kGoogleGrey200;
    case NativeTheme::kColorId_TextfieldReadOnlyBackground: {
      return color_utils::AlphaBlend(SK_ColorWHITE, gfx::kGoogleGrey900, 0.04f);
    }
    case NativeTheme::kColorId_TextfieldSelectionBackgroundFocused:
      return gfx::kGoogleBlue800;

    // Tooltip
    case NativeTheme::kColorId_TooltipText:
      return SkColorSetA(gfx::kGoogleGrey200, 0xDE);

    // Tree
    case NativeTheme::kColorId_TreeBackground:
      return color_utils::AlphaBlend(SK_ColorWHITE, gfx::kGoogleGrey900, 0.04f);
    case NativeTheme::kColorId_TreeText:
    case NativeTheme::kColorId_TreeSelectedText:
    case NativeTheme::kColorId_TreeSelectedTextUnfocused:
      return gfx::kGoogleGrey200;

    // Material spinner/throbber
    case NativeTheme::kColorId_ThrobberSpinningColor:
      return gfx::kGoogleBlue300;

    case NativeTheme::kColorId_BubbleBorder:
      return gfx::kGoogleGrey800;

    // Alert icon colors
    case NativeTheme::kColorId_AlertSeverityLow:
      return gfx::kGoogleGreen300;
    case NativeTheme::kColorId_AlertSeverityMedium:
      return gfx::kGoogleYellow300;
    case NativeTheme::kColorId_AlertSeverityHigh:
      return gfx::kGoogleRed300;

    case NativeTheme::kColorId_DefaultIconColor:
      return gfx::kGoogleGrey500;
    default:
      return base::nullopt;
  }
}

SkColor GetDefaultColor(NativeTheme::ColorId color_id,
                        const NativeTheme* base_theme,
                        NativeTheme::ColorScheme color_scheme) {
  constexpr SkColor kPrimaryTextColor = gfx::kGoogleGrey900;

  switch (color_id) {
    // Dialogs
    case NativeTheme::kColorId_WindowBackground:
    case NativeTheme::kColorId_DialogBackground:
    case NativeTheme::kColorId_BubbleBackground:
      return SK_ColorWHITE;
    case NativeTheme::kColorId_DialogForeground:
      return gfx::kGoogleGrey700;
    case NativeTheme::kColorId_BubbleForeground:
      return kPrimaryTextColor;
    case NativeTheme::kColorId_BubbleFooterBackground:
      return gfx::kGoogleGrey050;

    // Buttons
    case NativeTheme::kColorId_ButtonEnabledColor:
      return gfx::kGoogleBlue600;
    case NativeTheme::kColorId_ButtonInkDropShadowColor:
      return SkColorSetA(SK_ColorBLACK, 0x1A);
    case NativeTheme::kColorId_ButtonHoverColor:
      return SkColorSetA(SK_ColorBLACK, 0x05);
    case NativeTheme::kColorId_ButtonInkDropFillColor:
      return SkColorSetA(SK_ColorWHITE, 0x05);
    case NativeTheme::kColorId_ProminentButtonInkDropShadowColor:
      return SkColorSetA(SK_ColorBLACK, 0x3D);
    case NativeTheme::kColorId_ProminentButtonHoverColor:
      return SkColorSetA(SK_ColorWHITE, 0x0D);
    case NativeTheme::kColorId_ProminentButtonInkDropFillColor:
      return SkColorSetA(SK_ColorWHITE, 0x0D);
    case NativeTheme::kColorId_ProminentButtonFocusedColor: {
      const SkColor bg = base_theme->GetSystemColor(
          NativeTheme::kColorId_ProminentButtonColor, color_scheme);
      return color_utils::BlendForMinContrast(bg, bg, base::nullopt, 1.3f)
          .color;
    }
    case NativeTheme::kColorId_ProminentButtonColor:
    //modify by hanll, 修改确认按钮颜色, 2020/09/21， start
      return SkColorSetRGB(20,164,255);
      //return gfx::kGoogleBlue600;
    //modify by hanll, 修改确认按钮颜色, 2020/09/21， end
    case NativeTheme::kColorId_TextOnProminentButtonColor:
      return SK_ColorWHITE;
    case NativeTheme::kColorId_ButtonPressedShade:
      return SK_ColorTRANSPARENT;
    case NativeTheme::kColorId_ButtonUncheckedColor:
      return gfx::kGoogleGrey700;
    case NativeTheme::kColorId_ButtonDisabledColor: {
      const SkColor bg = base_theme->GetSystemColor(
          NativeTheme::kColorId_DialogBackground, color_scheme);
      const SkColor fg = base_theme->GetSystemColor(
          NativeTheme::kColorId_LabelEnabledColor, color_scheme);
      return color_utils::BlendForMinContrast(gfx::kGoogleGrey600, bg, fg)
          .color;
    }
    case NativeTheme::kColorId_ProminentButtonDisabledColor: {
      const SkColor bg = base_theme->GetSystemColor(
          NativeTheme::kColorId_DialogBackground, color_scheme);
      return color_utils::BlendForMinContrast(bg, bg, base::nullopt, 1.2f)
          .color;
    }
    case NativeTheme::kColorId_ButtonBorderColor:
      return gfx::kGoogleGrey300;
    case NativeTheme::kColorId_PaddedButtonInkDropColor:
      return gfx::kGoogleGrey900;

    // ToggleButton
    case NativeTheme::kColorId_ToggleButtonShadowColor:
      return SkColorSetA(
          base_theme->GetSystemColor(NativeTheme::kColorId_LabelEnabledColor,
                                     color_scheme),
          0x99);
    case ui::NativeTheme::kColorId_ToggleButtonTrackColorOff:
    case ui::NativeTheme::kColorId_ToggleButtonTrackColorOn: {
      const ui::NativeTheme::ColorId base_color_id =
          color_id == ui::NativeTheme::kColorId_ToggleButtonTrackColorOff
              ? ui::NativeTheme::kColorId_LabelEnabledColor
              : ui::NativeTheme::kColorId_ProminentButtonColor;
      return SkColorSetA(
          base_theme->GetSystemColor(base_color_id, color_scheme), 0x66);
    }

    // MenuItem
    case NativeTheme::kColorId_EnabledMenuItemForegroundColor:
      return base_theme->GetSystemColor(
          NativeTheme::kColorId_DropdownForegroundColor, color_scheme);
    //modify by xiaohuyang, Set the background color of the hover state of the menu item, 2020/09/15  --start
    case NativeTheme::kColorId_SelectedMenuItemForegroundColor:
#if 0
      return base_theme->GetSystemColor(
          NativeTheme::kColorId_DropdownSelectedForegroundColor, color_scheme);
#else
      return SkColorSetRGB(0xFF, 0xFF, 0xFF);
#endif
    case NativeTheme::kColorId_HighlightedMenuItemForegroundColor:
    case NativeTheme::kColorId_MenuDropIndicator:
      return kPrimaryTextColor;
    case NativeTheme::kColorId_FocusedMenuItemBackgroundColor:
#if 0
      return base_theme->GetSystemColor(
          NativeTheme::kColorId_DropdownSelectedBackgroundColor, color_scheme);
#else
      return SkColorSetRGB(0x00, 0x81, 0xFF);
#endif
    //modify by xiaohuyang, Set the background color of the hover state of the menu item, 2020/09/15  --end
    case NativeTheme::kColorId_MenuBorderColor:
    case NativeTheme::kColorId_MenuSeparatorColor:
      return gfx::kGoogleGrey300;
    case NativeTheme::kColorId_MenuBackgroundColor:
      return base_theme->GetSystemColor(
          NativeTheme::kColorId_DropdownBackgroundColor, color_scheme);
    case NativeTheme::kColorId_DisabledMenuItemForegroundColor: {
      const SkColor bg = base_theme->GetSystemColor(
          NativeTheme::kColorId_MenuBackgroundColor, color_scheme);
      const SkColor fg = base_theme->GetSystemColor(
          NativeTheme::kColorId_EnabledMenuItemForegroundColor, color_scheme);
      return color_utils::BlendForMinContrast(gfx::kGoogleGrey600, bg, fg)
          .color;
    }
    case NativeTheme::kColorId_MenuItemMinorTextColor:
      return gfx::kGoogleGrey700;
    case NativeTheme::kColorId_HighlightedMenuItemBackgroundColor:
      return gfx::kGoogleGrey050;
    case NativeTheme::kColorId_MenuItemInitialAlertBackgroundColor:
      return SkColorSetA(gfx::kGoogleBlue600, 0x4D);
    case NativeTheme::kColorId_MenuItemTargetAlertBackgroundColor:
      return SkColorSetA(gfx::kGoogleBlue600, 0x1A);

    // Custom frame view
    case NativeTheme::kColorId_CustomFrameActiveColor:
      return SkColorSetRGB(0xDE, 0xE1, 0xE6);
    case NativeTheme::kColorId_CustomFrameInactiveColor:
      return SkColorSetRGB(0xE7, 0xEA, 0xED);

    // Dropdown
    case NativeTheme::kColorId_DropdownBackgroundColor:
      return SK_ColorWHITE;
    case NativeTheme::kColorId_DropdownForegroundColor:
      return kPrimaryTextColor;
    case NativeTheme::kColorId_DropdownSelectedBackgroundColor: {
      const SkColor bg = base_theme->GetSystemColor(
          NativeTheme::kColorId_MenuBackgroundColor, color_scheme);
      return color_utils::BlendForMinContrast(bg, bg, base::nullopt, 1.67f)
          .color;
    }
    case NativeTheme::kColorId_DropdownSelectedForegroundColor:
      return kPrimaryTextColor;

    // Label
    case NativeTheme::kColorId_LabelEnabledColor:
    case NativeTheme::kColorId_LabelTextSelectionColor:
      return kPrimaryTextColor;
    case NativeTheme::kColorId_LabelDisabledColor: {
      const SkColor bg = base_theme->GetSystemColor(
          NativeTheme::kColorId_DialogBackground, color_scheme);
      const SkColor fg = base_theme->GetSystemColor(
          NativeTheme::kColorId_LabelEnabledColor, color_scheme);
      return color_utils::BlendForMinContrast(gfx::kGoogleGrey600, bg, fg)
          .color;
    }
    case NativeTheme::kColorId_LabelSecondaryColor:
      return gfx::kGoogleGrey700;
    case NativeTheme::kColorId_LabelTextSelectionBackgroundFocused:
      return gfx::kGoogleBlue200;

    // Link
    case NativeTheme::kColorId_LinkDisabled: {
      const SkColor bg = base_theme->GetSystemColor(
          NativeTheme::kColorId_DialogBackground, color_scheme);
      const SkColor fg = base_theme->GetSystemColor(
          NativeTheme::kColorId_LabelEnabledColor, color_scheme);
      return color_utils::BlendForMinContrast(gfx::kGoogleGrey600, bg, fg)
          .color;
    }
    case NativeTheme::kColorId_LinkEnabled:
    case NativeTheme::kColorId_LinkPressed:
      return gfx::kGoogleBlue600;

    // Scrollbar
    case NativeTheme::kColorId_OverlayScrollbarThumbBackground:
      return SK_ColorBLACK;
    case NativeTheme::kColorId_OverlayScrollbarThumbForeground:
      return SkColorSetA(SK_ColorWHITE, (kOverlayScrollbarStrokeNormalAlpha /
                                         kOverlayScrollbarThumbNormalAlpha) *
                                            SK_AlphaOPAQUE);

    // Slider
    case NativeTheme::kColorId_SliderThumbDefault:
      return SkColorSetARGB(0xFF, 0x25, 0x81, 0xDF);
    case NativeTheme::kColorId_SliderTroughDefault:
      return SkColorSetARGB(0x40, 0x25, 0x81, 0xDF);
    case NativeTheme::kColorId_SliderThumbMinimal:
      return SkColorSetARGB(0x6E, 0xF1, 0xF3, 0xF4);
    case NativeTheme::kColorId_SliderTroughMinimal:
      return SkColorSetARGB(0x19, 0xF1, 0xF3, 0xF4);

    // Separator
    case NativeTheme::kColorId_SeparatorColor:
      return gfx::kGoogleGrey300;

    // TabbedPane
    case NativeTheme::kColorId_TabTitleColorActive:
      return gfx::kGoogleBlue600;
    case NativeTheme::kColorId_TabTitleColorInactive:
      return gfx::kGoogleGrey700;
    case NativeTheme::kColorId_TabBottomBorder:
      return gfx::kGoogleGrey300;
    case NativeTheme::kColorId_TabHighlightBackground:
      return gfx::kGoogleBlue050;
    case NativeTheme::kColorId_TabHighlightFocusedBackground:
      return gfx::kGoogleBlue100;

    // Textfield
    case NativeTheme::kColorId_TextfieldDefaultColor:
    case NativeTheme::kColorId_TextfieldSelectionColor:
      return kPrimaryTextColor;
    case NativeTheme::kColorId_TextfieldDefaultBackground: {
      const SkColor fg = base_theme->GetSystemColor(
          NativeTheme::kColorId_TextfieldDefaultColor, color_scheme);
      // modify by xiaohuyang, Used to set the background color of textfiled,  2020/10/27
      // return color_utils::GetColorWithMaxContrast(fg);
      return color_utils::GetColorWithMaxContrastUOS(fg);
    }
    case NativeTheme::kColorId_TextfieldReadOnlyBackground:
      return SK_ColorWHITE;
    case NativeTheme::kColorId_TextfieldPlaceholderColor:
    case NativeTheme::kColorId_TextfieldReadOnlyColor: {
      const SkColor bg = base_theme->GetSystemColor(
          NativeTheme::kColorId_TextfieldReadOnlyBackground, color_scheme);
      const SkColor fg = base_theme->GetSystemColor(
          NativeTheme::kColorId_TextfieldDefaultColor, color_scheme);
      return color_utils::BlendForMinContrast(gfx::kGoogleGrey600, bg, fg)
          .color;
    }
    case NativeTheme::kColorId_TextfieldSelectionBackgroundFocused:
      return gfx::kGoogleBlue200;

    // Tooltip
    case NativeTheme::kColorId_TooltipBackground: {
      //modify by xiaohuyang, Set the background and text color of the tooltip, 2020/09/25  --start
#if 0
      const SkColor bg = base_theme->GetSystemColor(
          NativeTheme::kColorId_WindowBackground, color_scheme);
      return SkColorSetA(bg, 0xCC);
#else
      return SkColorSetRGB(0x54, 0x58, 0x68);
#endif
    }
    case NativeTheme::kColorId_TooltipIcon:
      return SkColorSetARGB(0xBD, 0x44, 0x44, 0x44);
    case NativeTheme::kColorId_TooltipIconHovered:
      return SkColorSetARGB(0xBD, 0, 0, 0);
    case NativeTheme::kColorId_TooltipText:
#if 0
      return SkColorSetA(kPrimaryTextColor, 0xDE);
#else
      return SkColorSetRGB(0xBA, 0xC3, 0xCF);
#endif
      //modify by xiaohuyang, Set the background color of the hover state of the menu item, 2020/09/25  --end

    // modify by hanll, 调整树控件点击时为蓝底白字的样子, 2020/09/24， start
    // Tree
    case NativeTheme::kColorId_TreeBackground:
      return SK_ColorWHITE;
    case NativeTheme::kColorId_TreeText:
      return kPrimaryTextColor;
    case NativeTheme::kColorId_TreeSelectedText:
    case NativeTheme::kColorId_TreeSelectedTextUnfocused:
      return SK_ColorWHITE;
    //  return kPrimaryTextColor;
    case NativeTheme::kColorId_TreeSelectionBackgroundFocused:
    case NativeTheme::kColorId_TreeSelectionBackgroundUnfocused: {
      #if UNUSE
        const SkColor bg = base_theme->GetSystemColor(
            NativeTheme::kColorId_TreeBackground, color_scheme);
        return color_utils::BlendForMinContrast(bg, bg, base::nullopt, 1.67f)
            .color;
      #else
        return SkColorSetARGB(255,0,129,255);
      #endif
    }
    // modify by hanll, 调整树控件点击时为蓝底白字的样子, 2020/09/24， end

    //modify by xiepinze, 2020/09/30, set selected table item background color, start
    // Table
    case NativeTheme::kColorId_TableBackground:
    case NativeTheme::kColorId_TableBackgroundAlternate:
      return SK_ColorWHITE;
    case NativeTheme::kColorId_TableText:
    //case NativeTheme::kColorId_TableSelectedText:
    //case NativeTheme::kColorId_TableSelectedTextUnfocused:
      return kPrimaryTextColor;
    case NativeTheme::kColorId_TableSelectedTextUnfocused:
    case NativeTheme::kColorId_TableSelectedText:
      return SkColorSetARGB(0xFF, 0xFF, 0xFF, 0xFF);
    case NativeTheme::kColorId_TableSelectionBackgroundFocused:
    case NativeTheme::kColorId_TableSelectionBackgroundUnfocused:
    case NativeTheme::kColorId_TableGroupingIndicatorColor: {
      //const SkColor bg = base_theme->GetSystemColor(
      //    NativeTheme::kColorId_TableBackground, color_scheme);
      //return color_utils::BlendForMinContrast(bg, bg, base::nullopt, 1.67f)
      //    .color;
      return SkColorSetARGB(255,0,129,255);
      //modify by xiepinze, 2020/09/30, set selected table item background color, end
    }

    // Table Header
    case NativeTheme::kColorId_TableHeaderText:
      return base_theme->GetSystemColor(NativeTheme::kColorId_TableText,
                                        color_scheme);
    case NativeTheme::kColorId_TableHeaderBackground:
      return base_theme->GetSystemColor(NativeTheme::kColorId_TableBackground,
                                        color_scheme);
    case NativeTheme::kColorId_TableHeaderSeparator:
      return base_theme->GetSystemColor(NativeTheme::kColorId_MenuBorderColor,
                                        color_scheme);

    // FocusableBorder
    case NativeTheme::kColorId_FocusedBorderColor:
      return SkColorSetA(gfx::kGoogleBlue600, 0x4D);
    case NativeTheme::kColorId_UnfocusedBorderColor:
      return gfx::kGoogleGrey300;

    // Material spinner/throbber
    case NativeTheme::kColorId_ThrobberSpinningColor:
      return gfx::kGoogleBlue600;
    case NativeTheme::kColorId_ThrobberWaitingColor:
      return SkColorSetRGB(0xA6, 0xA6, 0xA6);
    case NativeTheme::kColorId_ThrobberLightColor:
      return SkColorSetRGB(0xF4, 0xF8, 0xFD);

    // Alert icon colors
    case NativeTheme::kColorId_AlertSeverityLow:
      return gfx::kGoogleGreen700;
    case NativeTheme::kColorId_AlertSeverityMedium:
      return gfx::kGoogleYellow700;
    case NativeTheme::kColorId_AlertSeverityHigh:
      return gfx::kGoogleRed600;

    case NativeTheme::kColorId_DefaultIconColor:
      return gfx::kGoogleGrey700;

    // Sync info container
    case NativeTheme::kColorId_SyncInfoContainerPaused:
      return SkColorSetA(base_theme->GetSystemColor(
                             NativeTheme::kColorId_ProminentButtonColor),
                         16);
    case NativeTheme::kColorId_SyncInfoContainerError:
      return SkColorSetA(
          base_theme->GetSystemColor(NativeTheme::kColorId_AlertSeverityHigh),
          16);
    case NativeTheme::kColorId_SyncInfoContainerNoPrimaryAccount:
      return base_theme->GetSystemColor(
          NativeTheme::kColorId_BubbleFooterBackground);

    case NativeTheme::kColorId_BubbleBorder:
      return gfx::kGoogleGrey300;

    case NativeTheme::kColorId_NumColors:
      // Keeping the kColorId_NumColors case instead of using the default case
      // allows ColorId additions to trigger compile error for an incomplete
      // switch enumeration.
      NOTREACHED();
      return gfx::kPlaceholderColor;
  }
}

}  // namespace

SkColor GetAuraColor(NativeTheme::ColorId color_id,
                     const NativeTheme* base_theme,
                     NativeTheme::ColorScheme color_scheme) {
  if (color_scheme == NativeTheme::ColorScheme::kDefault)
    color_scheme = base_theme->GetDefaultSystemColorScheme();

  // High contrast overrides the normal colors for certain ColorIds to be much
  // darker or lighter.
  if (base_theme->UsesHighContrastColors()) {
    base::Optional<SkColor> color =
        GetHighContrastColor(color_id, color_scheme);
    if (color.has_value())
      return color.value();
  }

  if (color_scheme == NativeTheme::ColorScheme::kDark) {
    base::Optional<SkColor> color = GetDarkSchemeColor(color_id);
    if (color.has_value())
      return color.value();
  }

  return GetDefaultColor(color_id, base_theme, color_scheme);
}

void CommonThemePaintMenuItemBackground(
    const NativeTheme* theme,
    cc::PaintCanvas* canvas,
    NativeTheme::State state,
    const gfx::Rect& rect,
    const NativeTheme::MenuItemExtraParams& menu_item,
    NativeTheme::ColorScheme color_scheme) {
  cc::PaintFlags flags;
  switch (state) {
    case NativeTheme::kNormal:
    case NativeTheme::kDisabled:
      flags.setColor(theme->GetSystemColor(
          NativeTheme::kColorId_MenuBackgroundColor, color_scheme));
      break;
    case NativeTheme::kHovered:
      flags.setColor(theme->GetSystemColor(
          NativeTheme::kColorId_FocusedMenuItemBackgroundColor, color_scheme));
      break;
    default:
      NOTREACHED() << "Invalid state " << state;
      break;
  }
  if (menu_item.corner_radius > 0) {
    const SkScalar radius = SkIntToScalar(menu_item.corner_radius);
    canvas->drawRoundRect(gfx::RectToSkRect(rect), radius, radius, flags);
    return;
  }
  canvas->drawRect(gfx::RectToSkRect(rect), flags);
}

}  // namespace ui
