// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/views/controls/button/md_text_button.h"

#include <algorithm>
#include <utility>
#include <vector>

#include "base/i18n/case_conversion.h"
#include "base/memory/ptr_util.h"
#include "build/build_config.h"
#include "ui/gfx/canvas.h"
#include "ui/gfx/color_palette.h"
#include "ui/gfx/color_utils.h"
#include "ui/native_theme/native_theme.h"
#include "ui/views/animation/flood_fill_ink_drop_ripple.h"
#include "ui/views/animation/ink_drop_highlight.h"
#include "ui/views/animation/ink_drop_impl.h"
#include "ui/views/animation/ink_drop_painted_layer_delegates.h"
#include "ui/views/background.h"
#include "ui/views/border.h"
#include "ui/views/controls/focus_ring.h"
#include "ui/views/layout/layout_provider.h"
#include "ui/views/metadata/metadata_impl_macros.h"
#include "ui/views/painter.h"
#include "ui/views/style/platform_style.h"
#include "ui/views/style/typography.h"

#include "uos/dde/dde_appearance_theme_client.h"
#include "uos/dbus_thread_manager.h"

namespace views {

// static
std::unique_ptr<LabelButton> MdTextButton::CreateSecondaryUiButton(
    ButtonListener* listener,
    const base::string16& text) {
  //modify by xiaohuyang, Set the text color of the 'MdTextButton(cancel)' under different themes. 2021/1/21  --start
#if 0
  return MdTextButton::Create(listener, text, style::CONTEXT_BUTTON_MD);
#else
  auto button = MdTextButton::Create(listener, text, style::CONTEXT_BUTTON_MD);
  SkColor text_color;
  const bool use_dark_theme = 
      dbus::uos::DBusThreadManager::Get()->GetDdeAppearanceThemeClient()->isUseDarkColor();
  if (use_dark_theme) {
    text_color = SK_ColorWHITE;
  } else {
    text_color = SkColorSetRGB(0x41, 0x4d, 0x68);
  }
  button->SetEnabledTextColors(text_color);
  return button;
#endif
  //modify by xiaohuyang, Set the text color of the 'MdTextButton' under different themes. 2021/1/21  --end
}

// static
std::unique_ptr<LabelButton> MdTextButton::CreateSecondaryUiBlueButton(
    ButtonListener* listener,
    const base::string16& text) {
  auto md_button =
      MdTextButton::Create(listener, text, style::CONTEXT_BUTTON_MD);
  //modify by xiaohuyang, Set the text color of the 'MdTextButton(ok)' under different themes. 2021/1/21  --start
#if 1
  md_button->SetEnabledTextColors(SK_ColorWHITE);
#endif
  md_button->SetProminent(true);
  return md_button;
}

// static
std::unique_ptr<MdTextButton> MdTextButton::Create(ButtonListener* listener,
                                                   const base::string16& text,
                                                   int button_context) {
  auto button = base::WrapUnique<MdTextButton>(
      new MdTextButton(listener, button_context));
  button->SetText(text);
  button->SetFocusForPlatform();

  return button;
}

MdTextButton::~MdTextButton() = default;

void MdTextButton::SetProminent(bool is_prominent) {
  if (is_prominent_ == is_prominent)
    return;

  is_prominent_ = is_prominent;
  UpdateColors();
  OnPropertyChanged(&is_prominent_, kPropertyEffectsNone);
}

bool MdTextButton::GetProminent() const {
  return is_prominent_;
}

void MdTextButton::SetBgColorOverride(const base::Optional<SkColor>& color) {
  bg_color_override_ = color;
  UpdateColors();
  OnPropertyChanged(&bg_color_override_, kPropertyEffectsNone);
}

base::Optional<SkColor> MdTextButton::GetBgColorOverride() const {
  return bg_color_override_;
}

void MdTextButton::SetCornerRadius(float radius) {
  corner_radius_ = radius;
  set_ink_drop_corner_radii(corner_radius_, corner_radius_);
  OnPropertyChanged(&corner_radius_, kPropertyEffectsPaint);
}

float MdTextButton::GetCornerRadius() const {
  return corner_radius_;
}

// modify by xiaohuyang, Set the background color of the 'MdTextButton' under different themes. 2021/1/21
// This is a newly added function.
#if 1
void MdTextButton::OnPaintBackground(gfx::Canvas* canvas) {
  LabelButton::OnPaintBackground(canvas);
  if (hover_animation().is_animating() || state() == STATE_HOVERED) {
    bool should_use_dark_colors = GetNativeTheme()->ShouldUseDarkColors();
    int hover_alpha = is_prominent_ ? 0x0C : 0x05;
    if (should_use_dark_colors)
      hover_alpha = 0x0A;
    SkScalar alpha = hover_animation().CurrentValueBetween(0, hover_alpha);
    cc::PaintFlags flags;
    if (is_prominent_) {
      flags.setColor(SkColorSetA(SkColorSetRGB(0x00, 0x81, 0xFF), alpha));
    } else {
      if (should_use_dark_colors) {
        flags.setColor(SkColorSetA(SkColorSetRGB(0xE4, 0xE4, 0xE4), alpha));
      } else {
        flags.setColor(SkColorSetA(SkColorSetRGB(0x44, 0x44, 0x44), alpha));
      }
    }
      
    //flags.setColor(SkColorSetRGB(202,202,202));
    flags.setStyle(cc::PaintFlags::kFill_Style);
    flags.setAntiAlias(true);
    canvas->DrawRoundRect(gfx::RectF(GetLocalBounds()), corner_radius_, flags);
  }
}
#endif

void MdTextButton::OnThemeChanged() {
  LabelButton::OnThemeChanged();
  UpdateColors();
}

SkColor MdTextButton::GetInkDropBaseColor() const {
  return color_utils::DeriveDefaultIconColor(label()->GetEnabledColor());
}

void MdTextButton::StateChanged(ButtonState old_state) {
  LabelButton::StateChanged(old_state);
  UpdateColors();
}

void MdTextButton::OnFocus() {
  LabelButton::OnFocus();
  UpdateColors();
}

void MdTextButton::OnBlur() {
  LabelButton::OnBlur();
  UpdateColors();
}

std::unique_ptr<views::InkDropHighlight> MdTextButton::CreateInkDropHighlight()
    const {
  // modify by xiaohuyang, Set the inkdrop color of the 'MdTextButton' under different themes. 2021/1/21  --start
#if 0
  const ui::NativeTheme* theme = GetNativeTheme();
  // The prominent button hover effect is a shadow.
  constexpr int kYOffset = 1;
  constexpr int kSkiaBlurRadius = 2;
  ui::NativeTheme::ColorId fill_color_id;
  ui::NativeTheme::ColorId shadow_color_id =
      is_prominent_
          ? ui::NativeTheme::kColorId_ProminentButtonInkDropShadowColor
          : ui::NativeTheme::kColorId_ButtonInkDropShadowColor;
  if (state() == STATE_HOVERED) {
    fill_color_id = is_prominent_
                        ? ui::NativeTheme::kColorId_ProminentButtonHoverColor
                        : ui::NativeTheme::kColorId_ButtonHoverColor;
  } else {
    fill_color_id =
        is_prominent_
            ? ui::NativeTheme::kColorId_ProminentButtonInkDropFillColor
            : ui::NativeTheme::kColorId_ButtonInkDropFillColor;
  }
  std::vector<gfx::ShadowValue> shadows;
  // The notion of blur that gfx::ShadowValue uses is twice the Skia/CSS value.
  // Skia counts the number of pixels outside the mask area whereas
  // gfx::ShadowValue counts together the number of pixels inside and outside
  // the mask bounds.
  shadows.emplace_back(gfx::Vector2d(0, kYOffset), 2 * kSkiaBlurRadius,
                       theme->GetSystemColor(shadow_color_id));
  auto highlight = std::make_unique<InkDropHighlight>(
      gfx::RectF(GetLocalBounds()).CenterPoint(),
      std::make_unique<BorderShadowLayerDelegate>(
          shadows, GetLocalBounds(), theme->GetSystemColor(fill_color_id),
          corner_radius_));
  highlight->set_visible_opacity(1.0f);
  return highlight;
#else
  bool should_use_dark_colors = GetNativeTheme()->ShouldUseDarkColors();
  // The prominent button hover effect is a shadow.
  constexpr int kYOffset = 1;
  constexpr int kSkiaBlurRadius = 2;
  const int shadow_alpha = is_prominent_ ? 0x3D : 0x1A;
  // modify by xiaohuyang, Set shadow color.
  // const SkColor hover_color = should_use_dark_colors && !is_prominent_
  //                                   ? gfx::kGoogleBlue300
  //                                   : SK_ColorBLACK;
  const SkColor shadow_color = should_use_dark_colors && is_prominent_
                                   ? gfx::kGoogleBlue600
                                   : gfx::kGoogleGrey600;
  std::vector<gfx::ShadowValue> shadows;
  // The notion of blur that gfx::ShadowValue uses is twice the Skia/CSS value.
  // Skia counts the number of pixels outside the mask area whereas
  // gfx::ShadowValue counts together the number of pixels inside and outside
  // the mask bounds.
  shadows.emplace_back(
      gfx::Vector2d(0, kYOffset), 2 * kSkiaBlurRadius,
      SkColorSetA(shadow_color, should_use_dark_colors ? 0x7F : shadow_alpha));
  // modify by xiaohuyang, Set fill color.
  // const SkColor fill_color =
  //     SkColorSetA(SK_ColorWHITE, is_prominent_ ? 0x0D : 0x05);
  const SkColor fill_color =
      SkColorSetA(SkColorSetRGB(0x00, 0x81, 0xFF), is_prominent_ ? 0x00 : 0x05);
  return std::make_unique<InkDropHighlight>(
      gfx::RectF(GetLocalBounds()).CenterPoint(),
      base::WrapUnique(new BorderShadowLayerDelegate(
          shadows, GetLocalBounds(), fill_color, corner_radius_)));
#endif
  // modify by xiaohuyang, Set the inkdrop color of the 'MdTextButton' under different themes. 2021/1/21  --end
}

void MdTextButton::SetEnabledTextColors(base::Optional<SkColor> color) {
  LabelButton::SetEnabledTextColors(std::move(color));
  UpdateColors();
}

void MdTextButton::SetText(const base::string16& text) {
  LabelButton::SetText(text);
  UpdatePadding();
}

PropertyEffects MdTextButton::UpdateStyleToIndicateDefaultStatus() {
  is_prominent_ = is_prominent_ || GetIsDefault();
  UpdateColors();
  return kPropertyEffectsNone;
}

MdTextButton::MdTextButton(ButtonListener* listener, int button_context)
    : LabelButton(listener, base::string16(), button_context),
      is_prominent_(false) {
  SetInkDropMode(InkDropMode::ON);
  set_has_ink_drop_action_on_click(true);
#if 0
  set_show_ink_drop_when_hot_tracked(true);
  SetCornerRadius(LayoutProvider::Get()->GetCornerRadiusMetric(EMPHASIS_LOW));
#else
  SetCornerRadius(8.0f);
#endif
  SetHorizontalAlignment(gfx::ALIGN_CENTER);
  SetFocusForPlatform();
  const int minimum_width = LayoutProvider::Get()->GetDistanceMetric(
      DISTANCE_DIALOG_BUTTON_MINIMUM_WIDTH);
  SetMinSize(gfx::Size(minimum_width, 0));
  //Fix bug#81395. change "true" to "false" @xudongxu 2021/05/26 --start
  // SetInstallFocusRingOnFocus(true);
  SetInstallFocusRingOnFocus(false);
  //Fix bug#81395. change "true" to "false" @xudongxu 2021/05/26 --end
  label()->SetAutoColorReadabilityEnabled(false);
  set_request_focus_on_press(false);

  set_animate_on_state_change(true);

  // Paint to a layer so that the canvas is snapped to pixel boundaries (useful
  // for fractional DSF).
  SetPaintToLayer();
  layer()->SetFillsBoundsOpaquely(false);
}

void MdTextButton::UpdatePadding() {
  // Don't use font-based padding when there's no text visible.
  if (GetText().empty()) {
    SetBorder(NullBorder());
    return;
  }

  // Text buttons default to 28dp in height on all platforms when the base font
  // is in use, but should grow or shrink if the font size is adjusted up or
  // down. When the system font size has been adjusted, the base font will be
  // larger than normal such that 28dp might not be enough, so also enforce a
  // minimum height of twice the font size.
  // Example 1:
  // * Normal button on ChromeOS, 12pt Roboto. Button height of 28dp.
  // * Button on ChromeOS that has been adjusted to 14pt Roboto. Button height
  // of 28 + 2 * 2 = 32dp.
  // * Linux user sets base system font size to 17dp. For a normal button, the
  // |size_delta| will be zero, so to adjust upwards we double 17 to get 34.
  int size_delta =
      label()->font_list().GetFontSize() -
      style::GetFont(style::CONTEXT_BUTTON_MD, style::STYLE_PRIMARY)
          .GetFontSize();
  // TODO(tapted): This should get |target_height| using LayoutProvider::
  // GetControlHeightForFont().
  constexpr int kBaseHeight = 32;
  int target_height = std::max(kBaseHeight + size_delta * 2,
                               label()->font_list().GetFontSize() * 2);

  int label_height = label()->GetPreferredSize().height();
  int top_padding = (target_height - label_height) / 2;
  int bottom_padding = (target_height - label_height + 1) / 2;
  DCHECK_EQ(target_height, label_height + top_padding + bottom_padding);

  // TODO(estade): can we get rid of the platform style border hoopla if
  // we apply the MD treatment to all buttons, even GTK buttons?
  const int horizontal_padding = LayoutProvider::Get()->GetDistanceMetric(
      DISTANCE_BUTTON_HORIZONTAL_PADDING);
  SetBorder(CreateEmptyBorder(top_padding, horizontal_padding, bottom_padding,
                              horizontal_padding));
}

void MdTextButton::UpdateColors() {
  bool is_disabled = state() == STATE_DISABLED;
  SkColor enabled_text_color =
      style::GetColor(*this, label()->GetTextContext(),
                      is_prominent_ ? style::STYLE_DIALOG_BUTTON_DEFAULT
                                    : style::STYLE_PRIMARY);
  if (!explicitly_set_normal_color()) {
    const auto colors = explicitly_set_colors();
    LabelButton::SetEnabledTextColors(enabled_text_color);
    // Disabled buttons need the disabled color explicitly set.
    // This ensures that label()->GetEnabledColor() returns the correct color as
    // the basis for calculating the stroke color. enabled_text_color isn't used
    // since a descendant could have overridden the label enabled color.
    if (is_disabled) {
      LabelButton::SetTextColor(
          STATE_DISABLED, style::GetColor(*this, label()->GetTextContext(),
                                          style::STYLE_DISABLED));
    }
    set_explicitly_set_colors(colors);
  }

  // modify by xiaohuyang, Set the background color of the 'MdTextButton' under different themes. 2021/1/21  --start
#if 0
  ui::NativeTheme* theme = GetNativeTheme();
  SkColor bg_color = 
      theme->GetSystemColor(ui::NativeTheme::kColorId_DialogBackground);

  if (bg_color_override_) {
    bg_color = *bg_color_override_;
  } else if (is_prominent_) {
    bg_color = theme->GetSystemColor(
        HasFocus() ? ui::NativeTheme::kColorId_ProminentButtonFocusedColor
                   : ui::NativeTheme::kColorId_ProminentButtonColor);
    if (is_disabled) {
      bg_color = theme->GetSystemColor(
          ui::NativeTheme::kColorId_ProminentButtonDisabledColor);
    }
  }

  if (state() == STATE_PRESSED) {
    SkColor shade =
       theme->GetSystemColor(ui::NativeTheme::kColorId_ButtonPressedShade);
    bg_color = color_utils::GetResultingPaintColor(shade, bg_color);
  }

#else
  ui::NativeTheme* theme = GetNativeTheme();

  SkColor bg_color;
  if (GetNativeTheme()->ShouldUseDarkColors()) {
    bg_color = SkColorSetRGB(0x44, 0x44, 0x44);
  } else {
    bg_color = SkColorSetRGB(0xE4, 0xE4, 0xE4);
  }

  if (bg_color_override_) {
    bg_color = *bg_color_override_;
  } else if (is_prominent_) {
    bg_color = SkColorSetRGB(0x00, 0x81, 0xFF);
  }

  if (state() == STATE_PRESSED) {
    if (is_prominent_) {
      bg_color = SkColorSetRGB(0x00, 0x72, 0xEB);
    } else {
      if (GetNativeTheme()->ShouldUseDarkColors()) {
        bg_color = SkColorSetRGB(0x50, 0x50, 0x50);
      } else {
        bg_color = SkColorSetRGB(0xC4, 0xCC, 0xD7);
      }
    }
  }
#endif
  // modify by xiaohuyang, Set the background color of the 'MdTextButton' under different themes. 2021/1/21  --end

  SkColor stroke_color;
  if (is_prominent_) {
    stroke_color = SK_ColorTRANSPARENT;
  } else {
    stroke_color = SkColorSetA(
        theme->GetSystemColor(ui::NativeTheme::kColorId_ButtonBorderColor),
        is_disabled ? 0x43 : SK_AlphaOPAQUE);
  }

  SetBackground(
      CreateBackgroundFromPainter(Painter::CreateRoundRectWith1PxBorderPainter(
          bg_color, stroke_color, corner_radius_)));
  SchedulePaint();
}

BEGIN_METADATA(MdTextButton)
METADATA_PARENT_CLASS(LabelButton)
ADD_PROPERTY_METADATA(MdTextButton, bool, Prominent)
ADD_PROPERTY_METADATA(MdTextButton, float, CornerRadius)
ADD_PROPERTY_METADATA(MdTextButton, base::Optional<SkColor>, BgColorOverride)
END_METADATA()

}  // namespace views
