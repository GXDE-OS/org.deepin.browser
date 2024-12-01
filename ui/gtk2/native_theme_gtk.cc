// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/gtk2/native_theme_gtk.h"

#include <gtk/gtk.h>

#include "ui/gfx/color_palette.h"
#include "ui/gfx/color_utils.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/skbitmap_operations.h"
#include "ui/gfx/skia_util.h"
#include "ui/gtk2/gtk_util.h"

namespace gtk {

#if 1
namespace {

enum BackgroundRenderMode {
  BG_RENDER_NORMAL,
  BG_RENDER_NONE,
  BG_RENDER_RECURSIVE,
};

#if 0
ScopedStyleContext GetTooltipContext() {
  return AppendCssNodeToStyleContext(
      nullptr, GtkCheckVersion(3, 20) ? "#tooltip.background"
                                      : "GtkWindow#window.background.tooltip");
}

SkBitmap GetWidgetBitmap(const gfx::Size& size,
                         GtkStyleContext* context,
                         BackgroundRenderMode bg_mode,
                         bool render_frame) {
  DCHECK(bg_mode != BG_RENDER_NONE || render_frame);
  SkBitmap bitmap;
  bitmap.allocN32Pixels(size.width(), size.height());
  bitmap.eraseColor(0);

  CairoSurface surface(bitmap);
  cairo_t* cr = surface.cairo();

  switch (bg_mode) {
    case BG_RENDER_NORMAL:
      gtk_render_background(context, cr, 0, 0, size.width(), size.height());
      break;
    case BG_RENDER_RECURSIVE:
      RenderBackground(size, cr, context);
      break;
    case BG_RENDER_NONE:
      break;
  }
  if (render_frame)
    gtk_render_frame(context, cr, 0, 0, size.width(), size.height());
  bitmap.setImmutable();
  return bitmap;
}

void PaintWidget(cc::PaintCanvas* canvas,
                 const gfx::Rect& rect,
                 GtkStyleContext* context,
                 BackgroundRenderMode bg_mode,
                 bool render_frame) {
  canvas->drawImage(cc::PaintImage::CreateFromBitmap(GetWidgetBitmap(
                        rect.size(), context, bg_mode, render_frame)),
                    rect.x(), rect.y());
}
#endif

base::Optional<SkColor> SkColorFromColorId(
    ui::NativeTheme::ColorId color_id,
    const ui::NativeTheme* base_theme,
    ui::NativeTheme::ColorScheme color_scheme) {
#if 0
  switch (color_id) {
    // Windows
    case ui::NativeTheme::kColorId_WindowBackground:
    // Dialogs
    case ui::NativeTheme::kColorId_DialogBackground:
    case ui::NativeTheme::kColorId_BubbleBackground:
      return GetBgColor("");
    case ui::NativeTheme::kColorId_DialogForeground:
    case ui::NativeTheme::kColorId_BubbleForeground:
      return GetFgColor("GtkLabel");
    case ui::NativeTheme::kColorId_BubbleFooterBackground:
      return GetBgColor("#statusbar");

    // FocusableBorder
    case ui::NativeTheme::kColorId_FocusedBorderColor:
      // GetBorderColor("GtkEntry#entry:focus") is correct here.  The focus ring
      // around widgets is usually a lighter version of the "canonical theme
      // color" - orange on Ambiance, blue on Adwaita, etc.  However, Chrome
      // lightens the color we give it, so it would look wrong if we give it an
      // already-lightened color.  This workaround returns the theme color
      // directly, taken from a selected table row.  This has matched the theme
      // color on every theme that I've tested.
      return GetBgColor(
          "GtkTreeView#treeview.view "
          "GtkTreeView#treeview.view.cell:selected:focus");
    case ui::NativeTheme::kColorId_UnfocusedBorderColor:
      return GetBorderColor("GtkEntry#entry");

    // Menu
    case ui::NativeTheme::kColorId_MenuBackgroundColor:
    case ui::NativeTheme::kColorId_HighlightedMenuItemBackgroundColor:
    case ui::NativeTheme::kColorId_MenuItemInitialAlertBackgroundColor:
    case ui::NativeTheme::kColorId_MenuItemTargetAlertBackgroundColor:
      return GetBgColor("GtkMenu#menu");
    case ui::NativeTheme::kColorId_MenuBorderColor:
      return GetBorderColor("GtkMenu#menu");
    case ui::NativeTheme::kColorId_FocusedMenuItemBackgroundColor:
      return GetBgColor("GtkMenu#menu GtkMenuItem#menuitem:hover");
    case ui::NativeTheme::kColorId_EnabledMenuItemForegroundColor:
    case ui::NativeTheme::kColorId_MenuDropIndicator:
    case ui::NativeTheme::kColorId_HighlightedMenuItemForegroundColor:
      return GetFgColor("GtkMenu#menu GtkMenuItem#menuitem GtkLabel");
    case ui::NativeTheme::kColorId_SelectedMenuItemForegroundColor:
      return GetFgColor("GtkMenu#menu GtkMenuItem#menuitem:hover GtkLabel");
    case ui::NativeTheme::kColorId_DisabledMenuItemForegroundColor:
      return GetFgColor("GtkMenu#menu GtkMenuItem#menuitem:disabled GtkLabel");
    case ui::NativeTheme::kColorId_MenuItemMinorTextColor:
      if (GtkCheckVersion(3, 20)) {
        return GetFgColor("GtkMenu#menu GtkMenuItem#menuitem #accelerator");
      }
      return GetFgColor(
          "GtkMenu#menu GtkMenuItem#menuitem GtkLabel.accelerator");
    case ui::NativeTheme::kColorId_MenuSeparatorColor:
      if (GtkCheckVersion(3, 20)) {
        return GetSeparatorColor(
            "GtkMenu#menu GtkSeparator#separator.horizontal");
      }
      return GetFgColor("GtkMenu#menu GtkMenuItem#menuitem.separator");

    // Dropdown
    case ui::NativeTheme::kColorId_DropdownBackgroundColor:
      return GetBgColor(
          "GtkComboBoxText#combobox GtkWindow#window.background.popup "
          "GtkTreeMenu#menu(gtk-combobox-popup-menu) GtkMenuItem#menuitem "
          "GtkCellView#cellview");
    case ui::NativeTheme::kColorId_DropdownForegroundColor:
      return GetFgColor(
          "GtkComboBoxText#combobox GtkWindow#window.background.popup "
          "GtkTreeMenu#menu(gtk-combobox-popup-menu) GtkMenuItem#menuitem "
          "GtkCellView#cellview");
    case ui::NativeTheme::kColorId_DropdownSelectedBackgroundColor:
      return GetBgColor(
          "GtkComboBoxText#combobox GtkWindow#window.background.popup "
          "GtkTreeMenu#menu(gtk-combobox-popup-menu) "
          "GtkMenuItem#menuitem:hover GtkCellView#cellview");
    case ui::NativeTheme::kColorId_DropdownSelectedForegroundColor:
      return GetFgColor(
          "GtkComboBoxText#combobox GtkWindow#window.background.popup "
          "GtkTreeMenu#menu(gtk-combobox-popup-menu) "
          "GtkMenuItem#menuitem:hover GtkCellView#cellview");

    // Label
    case ui::NativeTheme::kColorId_LabelEnabledColor:
      return GetFgColor("GtkLabel");
    case ui::NativeTheme::kColorId_LabelDisabledColor:
    case ui::NativeTheme::kColorId_LabelSecondaryColor:
      return GetFgColor("GtkLabel:disabled");
    case ui::NativeTheme::kColorId_LabelTextSelectionColor:
      return GetFgColor(GtkCheckVersion(3, 20) ? "GtkLabel #selection"
                                               : "GtkLabel:selected");
    case ui::NativeTheme::kColorId_LabelTextSelectionBackgroundFocused:
      return GetSelectionBgColor(GtkCheckVersion(3, 20) ? "GtkLabel #selection"
                                                        : "GtkLabel:selected");

    // Link
    case ui::NativeTheme::kColorId_LinkDisabled:
      return SkColorSetA(
          base_theme->GetSystemColor(ui::NativeTheme::kColorId_LinkEnabled,
                                     color_scheme),
          0xBB);
    case ui::NativeTheme::kColorId_LinkPressed:
      if (GtkCheckVersion(3, 12))
        return GetFgColor("GtkLabel.link:link:hover:active");
      FALLTHROUGH;
    case ui::NativeTheme::kColorId_LinkEnabled: {
      if (GtkCheckVersion(3, 12))
        return GetFgColor("GtkLabel.link:link");
#if !GTK_CHECK_VERSION(3, 90, 0)
      auto link_context = GetStyleContextFromCss("GtkLabel.view");
      GdkColor* color;
      gtk_style_context_get_style(link_context, "link-color", &color, nullptr);
      if (color) {
        SkColor ret_color =
            SkColorSetRGB(color->red >> 8, color->green >> 8, color->blue >> 8);
        // gdk_color_free() was deprecated in Gtk3.14.  This code path is only
        // taken on versions earlier than Gtk3.12, but the compiler doesn't know
        // that, so silence the deprecation warnings.
        G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
        gdk_color_free(color);
        G_GNUC_END_IGNORE_DEPRECATIONS;
        return ret_color;
      }
#endif
      // Default color comes from gtklinkbutton.c.
      return SkColorSetRGB(0x00, 0x00, 0xEE);
    }

    // Scrollbar
    case ui::NativeTheme::kColorId_OverlayScrollbarThumbBackground:
      return GetBgColor("#GtkScrollbar#scrollbar #trough");
    case ui::NativeTheme::kColorId_OverlayScrollbarThumbForeground:
      return GetBgColor("#GtkScrollbar#scrollbar #slider");

    // Slider
    case ui::NativeTheme::kColorId_SliderThumbDefault:
      return GetBgColor("GtkScale#scale #highlight");
    case ui::NativeTheme::kColorId_SliderTroughDefault:
      return GetBgColor("GtkScale#scale #trough");
    case ui::NativeTheme::kColorId_SliderThumbMinimal:
      return GetBgColor("GtkScale#scale:disabled #highlight");
    case ui::NativeTheme::kColorId_SliderTroughMinimal:
      return GetBgColor("GtkScale#scale:disabled #trough");

    // Separator
    case ui::NativeTheme::kColorId_SeparatorColor:
      return GetSeparatorColor("GtkSeparator#separator.horizontal");

    // Button
    case ui::NativeTheme::kColorId_ButtonEnabledColor:
    case ui::NativeTheme::kColorId_ButtonUncheckedColor:
      return GetFgColor("GtkButton#button.text-button GtkLabel");
    case ui::NativeTheme::kColorId_ButtonDisabledColor:
      return GetFgColor("GtkButton#button.text-button:disabled GtkLabel");
    case ui::NativeTheme::kColorId_ButtonPressedShade:
      return SK_ColorTRANSPARENT;
    // TODO(thomasanderson): Add this once this CL lands:
    // https://chromium-review.googlesource.com/c/chromium/src/+/2053144
    // case ui::NativeTheme::kColorId_ButtonHoverColor:
    //   return GetBgColor("GtkButton#button:hover");

    // ProminentButton
    case ui::NativeTheme::kColorId_ProminentButtonColor:
    case ui::NativeTheme::kColorId_ProminentButtonFocusedColor:
      return GetBgColor(
          "GtkTreeView#treeview.view "
          "GtkTreeView#treeview.view.cell:selected:focus");
    case ui::NativeTheme::kColorId_TextOnProminentButtonColor:
      return GetFgColor(
          "GtkTreeView#treeview.view "
          "GtkTreeView#treeview.view.cell:selected:focus GtkLabel");
    case ui::NativeTheme::kColorId_ProminentButtonDisabledColor:
      return GetBgColor("GtkButton#button.text-button:disabled");
    case ui::NativeTheme::kColorId_ButtonBorderColor:
      return GetBorderColor("GtkButton#button.text-button");
    // TODO(thomasanderson): Add this once this CL lands:
    // https://chromium-review.googlesource.com/c/chromium/src/+/2053144
    // case ui::NativeTheme::kColorId_ProminentButtonHoverColor:
    //   return GetBgColor(
    //       "GtkTreeView#treeview.view "
    //       "GtkTreeView#treeview.view.cell:selected:focus:hover");

    // ToggleButton
    case ui::NativeTheme::kColorId_ToggleButtonTrackColorOff:
      return GetBgColor("GtkButton#button.text-button.toggle");
    case ui::NativeTheme::kColorId_ToggleButtonTrackColorOn:
      return GetBgColor("GtkButton#button.text-button.toggle:checked");

    // TabbedPane
    case ui::NativeTheme::kColorId_TabTitleColorActive:
      return GetFgColor("GtkLabel");
    case ui::NativeTheme::kColorId_TabTitleColorInactive:
      return GetFgColor("GtkLabel:disabled");
    case ui::NativeTheme::kColorId_TabBottomBorder:
      return GetBorderColor(GtkCheckVersion(3, 20) ? "GtkFrame#frame #border"
                                                   : "GtkFrame#frame");
    case ui::NativeTheme::kColorId_TabHighlightBackground:
      return GetBgColor("GtkNotebook#notebook #tab:checked");
    case ui::NativeTheme::kColorId_TabHighlightFocusedBackground:
      return GetBgColor("GtkNotebook#notebook:focus #tab:checked");

    // Textfield
    case ui::NativeTheme::kColorId_TextfieldDefaultColor:
      return GetFgColor(GtkCheckVersion(3, 20)
                            ? "GtkTextView#textview.view #text"
                            : "GtkTextView.view");
    case ui::NativeTheme::kColorId_TextfieldDefaultBackground:
      return GetBgColor(GtkCheckVersion(3, 20) ? "GtkTextView#textview.view"
                                               : "GtkTextView.view");
    case ui::NativeTheme::kColorId_TextfieldPlaceholderColor:
      if (!GtkCheckVersion(3, 90)) {
        auto context = GetStyleContextFromCss("GtkEntry#entry");
        // This is copied from gtkentry.c.
        GdkRGBA fg = {0.5, 0.5, 0.5};
        gtk_style_context_lookup_color(context, "placeholder_text_color", &fg);
        return GdkRgbaToSkColor(fg);
      }
      return GetFgColor("GtkEntry#entry #text #placeholder");
    case ui::NativeTheme::kColorId_TextfieldReadOnlyColor:
      return GetFgColor(GtkCheckVersion(3, 20)
                            ? "GtkTextView#textview.view:disabled #text"
                            : "GtkTextView.view:disabled");
    case ui::NativeTheme::kColorId_TextfieldReadOnlyBackground:
      return GetBgColor(GtkCheckVersion(3, 20)
                            ? "GtkTextView#textview.view:disabled"
                            : "GtkTextView.view:disabled");
    case ui::NativeTheme::kColorId_TextfieldSelectionColor:
      return GetFgColor(GtkCheckVersion(3, 20)
                            ? "GtkTextView#textview.view #text #selection"
                            : "GtkTextView.view:selected");
    case ui::NativeTheme::kColorId_TextfieldSelectionBackgroundFocused:
      return GetSelectionBgColor(
          GtkCheckVersion(3, 20) ? "GtkTextView#textview.view #text #selection"
                                 : "GtkTextView.view:selected");

    // Tooltips
    case ui::NativeTheme::kColorId_TooltipBackground:
      return GetBgColorFromStyleContext(GetTooltipContext());
    case ui::NativeTheme::kColorId_TooltipIcon:
      return GetFgColor("GtkButton#button.image-button");
    case ui::NativeTheme::kColorId_TooltipIconHovered:
      return GetFgColor("GtkButton#button.image-button:hover");
    case ui::NativeTheme::kColorId_TooltipText: {
      auto context = GetTooltipContext();
      context = AppendCssNodeToStyleContext(context, "GtkLabel");
      return GetFgColorFromStyleContext(context);
    }

    // Trees and Tables (implemented on GTK using the same class)
    case ui::NativeTheme::kColorId_TableBackground:
    case ui::NativeTheme::kColorId_TreeBackground:
      return GetBgColor(
          "GtkTreeView#treeview.view GtkTreeView#treeview.view.cell");
    case ui::NativeTheme::kColorId_TableText:
    case ui::NativeTheme::kColorId_TreeText:
    case ui::NativeTheme::kColorId_TableGroupingIndicatorColor:
      return GetFgColor(
          "GtkTreeView#treeview.view GtkTreeView#treeview.view.cell GtkLabel");
    case ui::NativeTheme::kColorId_TableSelectedText:
    case ui::NativeTheme::kColorId_TableSelectedTextUnfocused:
    case ui::NativeTheme::kColorId_TreeSelectedText:
    case ui::NativeTheme::kColorId_TreeSelectedTextUnfocused:
      return GetFgColor(
          "GtkTreeView#treeview.view "
          "GtkTreeView#treeview.view.cell:selected:focus GtkLabel");
    case ui::NativeTheme::kColorId_TableSelectionBackgroundFocused:
    case ui::NativeTheme::kColorId_TableSelectionBackgroundUnfocused:
    case ui::NativeTheme::kColorId_TreeSelectionBackgroundFocused:
    case ui::NativeTheme::kColorId_TreeSelectionBackgroundUnfocused:
      return GetBgColor(
          "GtkTreeView#treeview.view "
          "GtkTreeView#treeview.view.cell:selected:focus");

    // Table Header
    case ui::NativeTheme::kColorId_TableHeaderText:
      return GetFgColor("GtkTreeView#treeview.view GtkButton#button GtkLabel");
    case ui::NativeTheme::kColorId_TableHeaderBackground:
      return GetBgColor("GtkTreeView#treeview.view GtkButton#button");
    case ui::NativeTheme::kColorId_TableHeaderSeparator:
      return GetBorderColor("GtkTreeView#treeview.view GtkButton#button");

    // Throbber
    // TODO(thomasanderson): Render GtkSpinner directly.
    case ui::NativeTheme::kColorId_ThrobberSpinningColor:
      return GetFgColor("GtkSpinner#spinner");
    case ui::NativeTheme::kColorId_ThrobberWaitingColor:
    case ui::NativeTheme::kColorId_ThrobberLightColor:
      return GetFgColor("GtkSpinner#spinner:disabled");

    // Alert icons
    // Fallback to the same colors as Aura.
    case ui::NativeTheme::kColorId_AlertSeverityLow:
    case ui::NativeTheme::kColorId_AlertSeverityMedium:
    case ui::NativeTheme::kColorId_AlertSeverityHigh: {
      // Alert icons appear on the toolbar, so use the toolbar BG
      // color (the GTK window bg color) to determine if the dark
      // or light native theme should be used for the icons.
      ui::NativeTheme* fallback_theme =
          color_utils::IsDark(GetBgColor(""))
              ? ui::NativeTheme::GetInstanceForDarkUI()
              : ui::NativeTheme::GetInstanceForNativeUi();
      return fallback_theme->GetSystemColor(color_id);
    }

    case ui::NativeTheme::kColorId_DefaultIconColor:
      if (GtkCheckVersion(3, 20))
        return GetFgColor("GtkMenu#menu GtkMenuItem#menuitem #radio");
      return GetFgColor("GtkMenu#menu GtkMenuItem#menuitem.radio");

    case ui::NativeTheme::kColorId_NumColors:
      NOTREACHED();
      break;

    default:
      break;
  }
  return base::nullopt;
#else
  return base::nullopt;
#endif
}

}  // namespace

// static
NativeThemeGtk* NativeThemeGtk::instance() {
  static base::NoDestructor<NativeThemeGtk> s_native_theme;
  return s_native_theme.get();
}

NativeThemeGtk::NativeThemeGtk() {
  // These types are needed by g_type_from_name(), but may not be registered at
  // this point.  We need the g_type_class magic to make sure the compiler
  // doesn't optimize away this code.
  g_type_class_unref(g_type_class_ref(gtk_button_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_entry_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_frame_get_type()));
  //g_type_class_unref(g_type_class_ref(gtk_header_bar_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_image_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_info_bar_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_label_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_menu_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_menu_bar_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_menu_item_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_range_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_scrollbar_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_scrolled_window_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_separator_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_spinner_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_text_view_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_toggle_button_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_tree_view_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_window_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_combo_box_text_get_type()));
  g_type_class_unref(g_type_class_ref(gtk_cell_view_get_type()));

  // Initialize the GtkTreeMenu type.  _gtk_tree_menu_get_type() is private, so
  // we need to initialize it indirectly.
  ScopedGObject<GtkTreeModel> model{
      GTK_TREE_MODEL(gtk_tree_store_new(1, G_TYPE_STRING))};
  ScopedGObject<GtkWidget> combo{gtk_combo_box_new_with_model(model)};

  OnThemeChanged(gtk_settings_get_default(), nullptr);
}

NativeThemeGtk::~NativeThemeGtk() {
  NOTREACHED();
}

#if 0
void NativeThemeGtk::SetThemeCssOverride(ScopedCssProvider provider) {
  if (theme_css_override_) {
    gtk_style_context_remove_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(theme_css_override_.get()));
  }
  theme_css_override_ = std::move(provider);
  if (theme_css_override_) {
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(theme_css_override_.get()),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
  }
}
#endif

void NativeThemeGtk::OnThemeChanged(GtkSettings* settings,
                                    GtkParamSpec* param) {
#if 0
  SetThemeCssOverride(ScopedCssProvider());
  for (auto& color : color_cache_)
    color = base::nullopt;

  // Hack to workaround a bug on GNOME standard themes which would
  // cause black patches to be rendered on GtkFileChooser dialogs.
  std::string theme_name =
      GetGtkSettingsStringProperty(settings, "gtk-theme-name");
  if (!GtkCheckVersion(3, 14)) {
    if (theme_name == "Adwaita") {
      SetThemeCssOverride(GetCssProvider(
          "GtkFileChooser GtkPaned { background-color: @theme_bg_color; }"));
    } else if (theme_name == "HighContrast") {
      SetThemeCssOverride(GetCssProvider(
          "GtkFileChooser GtkPaned { background-color: @theme_base_color; }"));
    }
  }

  // GTK has a dark mode setting called "gtk-application-prefer-dark-theme", but
  // this is really only used for themes that have a dark or light variant that
  // gets toggled based on this setting (eg. Adwaita).  Most dark themes do not
  // have a light variant and aren't affected by the setting.  Because of this,
  // experimentally check if the theme is dark by checking if the window
  // background color is dark.
  set_use_dark_colors(
      color_utils::IsDark(GetSystemColor(kColorId_WindowBackground)));
  set_preferred_color_scheme(CalculatePreferredColorScheme());

  // GTK doesn't have a native high contrast setting.  Rather, it's implied by
  // the theme name.  The only high contrast GTK themes that I know of are
  // HighContrast (GNOME) and ContrastHighInverse (MATE).  So infer the contrast
  // based on if the theme name contains both "high" and "contrast",
  // case-insensitive.
  std::transform(theme_name.begin(), theme_name.end(), theme_name.begin(),
                 ::tolower);
  set_high_contrast(theme_name.find("high") != std::string::npos &&
                    theme_name.find("contrast") != std::string::npos);

  NotifyObservers();
#endif
}

SkColor NativeThemeGtk::GetSystemColor(ColorId color_id,
                                       ColorScheme color_scheme) const {
  base::Optional<SkColor> color = color_cache_[color_id];
  if (!color) {
    color = SkColorFromColorId(color_id, this, color_scheme);
    if (!color)
      color = ui::NativeThemeBase::GetSystemColor(color_id, color_scheme);
    color_cache_[color_id] = color;
  }
  DCHECK(color);
  return color.value();
}

void NativeThemeGtk::PaintArrowButton(
    cc::PaintCanvas* canvas,
    const gfx::Rect& rect,
    Part direction,
    State state,
    ColorScheme color_scheme,
    const ScrollbarArrowExtraParams& arrow) const {
#if 0
  auto context = GetStyleContextFromCss(
          0
          ? "GtkScrollbar#scrollbar #contents GtkButton#button"
          : "GtkRange.scrollbar.button");
  GtkStateFlags state_flags = StateToStateFlags(state);
  gtk_style_context_set_state(context, state_flags);

  switch (direction) {
    case kScrollbarUpArrow:
      gtk_style_context_add_class(context, GTK_STYLE_CLASS_TOP);
      break;
    case kScrollbarRightArrow:
      gtk_style_context_add_class(context, GTK_STYLE_CLASS_RIGHT);
      break;
    case kScrollbarDownArrow:
      gtk_style_context_add_class(context, GTK_STYLE_CLASS_BOTTOM);
      break;
    case kScrollbarLeftArrow:
      gtk_style_context_add_class(context, GTK_STYLE_CLASS_LEFT);
      break;
    default:
      NOTREACHED();
  }

  PaintWidget(canvas, rect, context, BG_RENDER_NORMAL, true);
  PaintArrow(canvas, rect, direction, GetFgColorFromStyleContext(context));
#endif
}

void NativeThemeGtk::PaintScrollbarTrack(
    cc::PaintCanvas* canvas,
    Part part,
    State state,
    const ScrollbarTrackExtraParams& extra_params,
    const gfx::Rect& rect,
    ColorScheme color_scheme) const {
#if 0
  PaintWidget(
      canvas, rect,
      GetStyleContextFromCss(0
                             ? "GtkScrollbar#scrollbar #contents #trough"
                             : "GtkScrollbar.scrollbar.trough"),
      BG_RENDER_NORMAL, true);
#endif
}

void NativeThemeGtk::PaintScrollbarThumb(
    cc::PaintCanvas* canvas,
    Part part,
    State state,
    const gfx::Rect& rect,
    NativeTheme::ScrollbarOverlayColorTheme theme,
    ColorScheme color_scheme) const {
#if 0
  auto context = GetStyleContextFromCss(
          0
          ? "GtkScrollbar#scrollbar #contents #trough #slider"
          : "GtkScrollbar.scrollbar.slider");
  gtk_style_context_set_state(context, StateToStateFlags(state));
  PaintWidget(canvas, rect, context, BG_RENDER_NORMAL, true);
#endif
}

void NativeThemeGtk::PaintScrollbarCorner(cc::PaintCanvas* canvas,
                                          State state,
                                          const gfx::Rect& rect,
                                          ColorScheme color_scheme) const {
#if 0
  auto context = GetStyleContextFromCss(
          0
          ? "GtkScrolledWindow#scrolledwindow #junction"
          : "GtkScrolledWindow.scrolledwindow.scrollbars-junction");
  PaintWidget(canvas, rect, context, BG_RENDER_NORMAL, true);
#endif
}

void NativeThemeGtk::PaintMenuPopupBackground(
    cc::PaintCanvas* canvas,
    const gfx::Size& size,
    const MenuBackgroundExtraParams& menu_background,
    ColorScheme color_scheme) const {
#if 0
  PaintWidget(canvas, gfx::Rect(size), GetStyleContextFromCss("GtkMenu#menu"),
              BG_RENDER_RECURSIVE, false);
#else
  if (menu_background.corner_radius > 0) {
    cc::PaintFlags flags;
    flags.setStyle(cc::PaintFlags::kFill_Style);
    flags.setAntiAlias(true);
    flags.setColor(GetSystemColor(kColorId_MenuBackgroundColor));

    SkPath path;
    SkRect rect = SkRect::MakeWH(SkIntToScalar(size.width()),
                                 SkIntToScalar(size.height()));
    SkScalar radius = SkIntToScalar(menu_background.corner_radius);
    SkScalar radii[8] = {radius, radius, radius, radius,
                         radius, radius, radius, radius};
    path.addRoundRect(rect, radii);

    canvas->drawPath(path, flags);
  } else {
    canvas->drawColor(GetSystemColor(kColorId_MenuBackgroundColor),
                      SkBlendMode::kSrc);
  }
#endif
}

void NativeThemeGtk::PaintMenuItemBackground(
    cc::PaintCanvas* canvas,
    State state,
    const gfx::Rect& rect,
    const MenuItemExtraParams& menu_item,
    ColorScheme color_scheme) const {
#if 0
  auto context = GetStyleContextFromCss("GtkMenu#menu GtkMenuItem#menuitem");
  gtk_style_context_set_state(context, StateToStateFlags(state));
  PaintWidget(canvas, rect, context, BG_RENDER_NORMAL, true);
#else
  SkColor color;
  cc::PaintFlags flags;
  switch (state) {
    case NativeTheme::kNormal:
    case NativeTheme::kDisabled:
      color = GetSystemColor(NativeTheme::kColorId_MenuBackgroundColor);
      flags.setColor(color);
      break;
    case NativeTheme::kHovered:
      color =
          GetSystemColor(NativeTheme::kColorId_FocusedMenuItemBackgroundColor);
      flags.setColor(color);
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
#endif
}

void NativeThemeGtk::PaintMenuSeparator(
    cc::PaintCanvas* canvas,
    State state,
    const gfx::Rect& rect,
    const MenuSeparatorExtraParams& menu_separator,
    ColorScheme color_scheme) const {
  // TODO(estade): use GTK to draw vertical separators too. See
  // crbug.com/710183
  if (menu_separator.type == ui::VERTICAL_SEPARATOR) {
    cc::PaintFlags paint;
    paint.setStyle(cc::PaintFlags::kFill_Style);
    paint.setColor(GetSystemColor(ui::NativeTheme::kColorId_MenuSeparatorColor,
                                  color_scheme));
    canvas->drawRect(gfx::RectToSkRect(rect), paint);
    return;
  }

  auto separator_offset = [&](int separator_thickness) {
    switch (menu_separator.type) {
      case ui::LOWER_SEPARATOR:
        return rect.height() - separator_thickness;
      case ui::UPPER_SEPARATOR:
        return 0;
      default:
        return (rect.height() - separator_thickness) / 2;
    }
  };
#if 0
  if (0) {
    auto context = GetStyleContextFromCss(
        "GtkMenu#menu GtkSeparator#separator.horizontal");
    GtkBorder margin, border, padding;
    int min_height = 1;
#if GTK_CHECK_VERSION(3, 90, 0)
    gtk_style_context_get_margin(context, &margin);
    gtk_style_context_get_border(context, &border);
    gtk_style_context_get_padding(context, &padding);
    gtk_style_context_get(context, "min-height", &min_height, nullptr);
#else
    GtkStateFlags state = gtk_style_context_get_state(context);
    gtk_style_context_get_margin(context, state, &margin);
    gtk_style_context_get_border(context, state, &border);
    gtk_style_context_get_padding(context, state, &padding);
    gtk_style_context_get(context, state, "min-height", &min_height, nullptr);
#endif
    int w = rect.width() - margin.left - margin.right;
    int h = std::max(
        min_height + padding.top + padding.bottom + border.top + border.bottom,
        1);
    int x = margin.left;
    int y = separator_offset(h);
    PaintWidget(canvas, gfx::Rect(x, y, w, h), context, BG_RENDER_NORMAL, true);
  } else {
#if !GTK_CHECK_VERSION(3, 90, 0)
    auto context = GetStyleContextFromCss(
        "GtkMenu#menu GtkMenuItem#menuitem.separator.horizontal");
    gboolean wide_separators = false;
    gint separator_height = 0;
    gtk_style_context_get_style(context, "wide-separators", &wide_separators,
                                "separator-height", &separator_height, nullptr);
    // This code was adapted from gtk/gtkmenuitem.c.  For some reason,
    // padding is used as the margin.
    GtkBorder padding;
    gtk_style_context_get_padding(context, gtk_style_context_get_state(context),
                                  &padding);
    int w = rect.width() - padding.left - padding.right;
    int x = rect.x() + padding.left;
    int h = wide_separators ? separator_height : 1;
    int y = rect.y() + separator_offset(h);
    if (wide_separators) {
      PaintWidget(canvas, gfx::Rect(x, y, w, h), context, BG_RENDER_NONE, true);
    } else {
      cc::PaintFlags flags;
      flags.setColor(GetFgColorFromStyleContext(context));
      flags.setAntiAlias(true);
      flags.setStrokeWidth(1);
      canvas->drawLine(x + 0.5f, y + 0.5f, x + w + 0.5f, y + 0.5f, flags);
    }
#endif
  }
#endif
}

void NativeThemeGtk::PaintFrameTopArea(
    cc::PaintCanvas* canvas,
    State state,
    const gfx::Rect& rect,
    const FrameTopAreaExtraParams& frame_top_area,
    ColorScheme color_scheme) const {
#if 0
  auto context = GetStyleContextFromCss(frame_top_area.use_custom_frame
                                            ? "#headerbar.header-bar.titlebar"
                                            : "GtkMenuBar#menubar");
  ApplyCssToContext(context, "* { border-radius: 0px; border-style: none; }");
  gtk_style_context_set_state(context, frame_top_area.is_active
                                           ? GTK_STATE_FLAG_NORMAL
                                           : GTK_STATE_FLAG_BACKDROP);

  SkBitmap bitmap =
      GetWidgetBitmap(rect.size(), context, BG_RENDER_RECURSIVE, false);

  if (frame_top_area.incognito) {
    bitmap = SkBitmapOperations::CreateHSLShiftedBitmap(
        bitmap, kDefaultTintFrameIncognito);
    bitmap.setImmutable();
  }

  canvas->drawImage(cc::PaintImage::CreateFromBitmap(std::move(bitmap)),
                    rect.x(), rect.y());
#endif
}
#else
namespace {

enum WidgetState {
  NORMAL = 0,
  ACTIVE = 1,
  PRELIGHT = 2,
  SELECTED = 3,
  INSENSITIVE = 4,
};

// Same order as enum WidgetState above
const GtkStateType stateMap[] = {
    GTK_STATE_NORMAL,   GTK_STATE_ACTIVE,      GTK_STATE_PRELIGHT,
    GTK_STATE_SELECTED, GTK_STATE_INSENSITIVE,
};

SkColor GetFgColor(GtkWidget* widget, WidgetState state) {
  return GdkColorToSkColor(gtk_rc_get_style(widget)->fg[stateMap[state]]);
}
SkColor GetBgColor(GtkWidget* widget, WidgetState state) {
  return GdkColorToSkColor(gtk_rc_get_style(widget)->bg[stateMap[state]]);
}

SkColor GetTextColor(GtkWidget* widget, WidgetState state) {
  return GdkColorToSkColor(gtk_rc_get_style(widget)->text[stateMap[state]]);
}
SkColor GetTextAAColor(GtkWidget* widget, WidgetState state) {
  return GdkColorToSkColor(gtk_rc_get_style(widget)->text_aa[stateMap[state]]);
}
SkColor GetBaseColor(GtkWidget* widget, WidgetState state) {
  return GdkColorToSkColor(gtk_rc_get_style(widget)->base[stateMap[state]]);
}

}  // namespace

// static
NativeThemeGtk* NativeThemeGtk::instance() {
  CR_DEFINE_STATIC_LOCAL(NativeThemeGtk, s_native_theme, ());
  return &s_native_theme;
}

// Constructors automatically called
NativeThemeGtk::NativeThemeGtk() {}
// This doesn't actually get called
NativeThemeGtk::~NativeThemeGtk() {}

void NativeThemeGtk::PaintMenuPopupBackground(
    cc::PaintCanvas* canvas,
    const gfx::Size& size,
    const MenuBackgroundExtraParams& menu_background) const {
  if (menu_background.corner_radius > 0) {
    cc::PaintFlags flags;
    flags.setStyle(cc::PaintFlags::kFill_Style);
    flags.setAntiAlias(true);
    flags.setColor(GetSystemColor(kColorId_MenuBackgroundColor));

    gfx::Path path;
    SkRect rect = SkRect::MakeWH(SkIntToScalar(size.width()),
                                 SkIntToScalar(size.height()));
    SkScalar radius = SkIntToScalar(menu_background.corner_radius);
    SkScalar radii[8] = {radius, radius, radius, radius,
                         radius, radius, radius, radius};
    path.addRoundRect(rect, radii);

    canvas->drawPath(path, flags);
  } else {
    canvas->drawColor(GetSystemColor(kColorId_MenuBackgroundColor),
                      SkBlendMode::kSrc);
  }
}

void NativeThemeGtk::PaintMenuItemBackground(
    cc::PaintCanvas* canvas,
    State state,
    const gfx::Rect& rect,
    const MenuItemExtraParams& menu_item) const {
  SkColor color;
  cc::PaintFlags flags;
  switch (state) {
    case NativeTheme::kNormal:
    case NativeTheme::kDisabled:
      color = GetSystemColor(NativeTheme::kColorId_MenuBackgroundColor);
      flags.setColor(color);
      break;
    case NativeTheme::kHovered:
      color =
          GetSystemColor(NativeTheme::kColorId_FocusedMenuItemBackgroundColor);
      flags.setColor(color);
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

SkColor NativeThemeGtk::GetSystemColor(ColorId color_id) const {
  const SkColor kPositiveTextColor = SkColorSetRGB(0x0b, 0x80, 0x43);
  const SkColor kNegativeTextColor = SkColorSetRGB(0xc5, 0x39, 0x29);

  switch (color_id) {
    // Windows
    case kColorId_WindowBackground:
      return GetBgColor(GetWindow(), SELECTED);

    // Dialogs
    case kColorId_DialogBackground:
    case kColorId_BubbleBackground:
      return GetBgColor(GetWindow(), NORMAL);

    // FocusableBorder
    case kColorId_FocusedBorderColor:
      return GetBgColor(GetEntry(), SELECTED);
    case kColorId_UnfocusedBorderColor:
      return GetTextAAColor(GetEntry(), NORMAL);

    // MenuItem
    case kColorId_SelectedMenuItemForegroundColor:
      return GetTextColor(GetMenuItem(), SELECTED);
    case kColorId_FocusedMenuItemBackgroundColor:
      return GetBgColor(GetMenuItem(), SELECTED);

    case kColorId_EnabledMenuItemForegroundColor:
      return GetTextColor(GetMenuItem(), NORMAL);
    case kColorId_MenuItemMinorTextColor:
    case kColorId_DisabledMenuItemForegroundColor:
      return GetTextColor(GetMenuItem(), INSENSITIVE);
    case kColorId_MenuBorderColor:
    case kColorId_MenuSeparatorColor:
      return GetTextColor(GetMenuItem(), INSENSITIVE);
    case kColorId_MenuBackgroundColor:
      return GetBgColor(GetMenu(), NORMAL);
    case kColorId_TouchableMenuItemLabelColor:
    case kColorId_ActionableSubmenuVerticalSeparatorColor:
      return kInvalidColorIdColor;

    // Label
    case kColorId_LabelEnabledColor:
      return GetTextColor(GetEntry(), NORMAL);
    case kColorId_LabelDisabledColor:
      return GetTextColor(GetLabel(), INSENSITIVE);
    case kColorId_LabelTextSelectionColor:
      return GetTextColor(GetLabel(), SELECTED);
    case kColorId_LabelTextSelectionBackgroundFocused:
      return GetBaseColor(GetLabel(), SELECTED);

    // Link
    case kColorId_LinkDisabled:
      return SkColorSetA(GetSystemColor(kColorId_LinkEnabled), 0xBB);
    case kColorId_LinkEnabled: {
      SkColor link_color = SK_ColorTRANSPARENT;
      GdkColor* style_color = nullptr;
      gtk_widget_style_get(GetWindow(), "link-color", &style_color, nullptr);
      if (style_color) {
        link_color = GdkColorToSkColor(*style_color);
        gdk_color_free(style_color);
      }
      if (link_color != SK_ColorTRANSPARENT)
        return link_color;
      // Default color comes from gtklinkbutton.c.
      return SkColorSetRGB(0x00, 0x00, 0xEE);
    }
    case kColorId_LinkPressed:
      return SK_ColorRED;

    // Separator
    case kColorId_SeparatorColor:
      return GetFgColor(GetSeparator(), INSENSITIVE);

    // Button
    case kColorId_ButtonEnabledColor:
      return GetTextColor(GetButton(), NORMAL);
    case kColorId_BlueButtonEnabledColor:
      return GetTextColor(GetBlueButton(), NORMAL);
    case kColorId_ButtonDisabledColor:
      return GetTextColor(GetButton(), INSENSITIVE);
    case kColorId_BlueButtonDisabledColor:
      return GetTextColor(GetBlueButton(), INSENSITIVE);
    case kColorId_ButtonHoverColor:
      return GetTextColor(GetButton(), PRELIGHT);
    case kColorId_BlueButtonHoverColor:
      return GetTextColor(GetBlueButton(), PRELIGHT);
    case kColorId_BlueButtonPressedColor:
      return GetTextColor(GetBlueButton(), ACTIVE);
    case kColorId_BlueButtonShadowColor:
      return SK_ColorTRANSPARENT;
    case kColorId_ProminentButtonColor:
      return GetSystemColor(kColorId_LinkEnabled);
    case kColorId_TextOnProminentButtonColor:
      return GetTextColor(GetLabel(), SELECTED);
    case kColorId_ButtonPressedShade:
      return SK_ColorTRANSPARENT;

    // TabbedPane
    case ui::NativeTheme::kColorId_TabTitleColorActive:
      return GetTextColor(GetEntry(), NORMAL);
    case ui::NativeTheme::kColorId_TabTitleColorInactive:
      return GetTextColor(GetLabel(), INSENSITIVE);
    case ui::NativeTheme::kColorId_TabBottomBorder:
      return GetTextColor(GetEntry(), NORMAL);

    // Textfield
    case kColorId_TextfieldDefaultColor:
      return GetTextColor(GetEntry(), NORMAL);
    case kColorId_TextfieldDefaultBackground:
      return GetBaseColor(GetEntry(), NORMAL);

    case kColorId_TextfieldReadOnlyColor:
      return GetTextColor(GetEntry(), ACTIVE);
    case kColorId_TextfieldReadOnlyBackground:
      return GetBaseColor(GetEntry(), ACTIVE);
    case kColorId_TextfieldSelectionColor:
      return GetTextColor(GetEntry(), SELECTED);
    case kColorId_TextfieldSelectionBackgroundFocused:
      return GetBaseColor(GetEntry(), SELECTED);

    // Tooltips
    case kColorId_TooltipBackground:
      return GetBgColor(GetTooltip(), NORMAL);
    case kColorId_TooltipText:
      return GetFgColor(GetTooltip(), NORMAL);

    // Trees and Tables (implemented on GTK using the same class)
    case kColorId_TableBackground:
    case kColorId_TreeBackground:
      return GetBgColor(GetTree(), NORMAL);
    case kColorId_TableText:
    case kColorId_TreeText:
      return GetTextColor(GetTree(), NORMAL);
    case kColorId_TableSelectedText:
    case kColorId_TableSelectedTextUnfocused:
    case kColorId_TreeSelectedText:
    case kColorId_TreeSelectedTextUnfocused:
      return GetTextColor(GetTree(), SELECTED);
    case kColorId_TableSelectionBackgroundFocused:
    case kColorId_TableSelectionBackgroundUnfocused:
    case kColorId_TreeSelectionBackgroundFocused:
    case kColorId_TreeSelectionBackgroundUnfocused:
      return GetBgColor(GetTree(), SELECTED);
    case kColorId_TableGroupingIndicatorColor:
      return GetTextAAColor(GetTree(), NORMAL);

    // Table Headers
    case kColorId_TableHeaderText:
      return GetTextColor(GetTree(), NORMAL);
    case kColorId_TableHeaderBackground:
      return GetBgColor(GetTree(), NORMAL);
    case kColorId_TableHeaderSeparator:
      return GetFgColor(GetSeparator(), INSENSITIVE);

    // Results Table
    case kColorId_ResultsTableNormalBackground:
      return GetSystemColor(kColorId_TextfieldDefaultBackground);
    case kColorId_ResultsTableHoveredBackground:
      return color_utils::AlphaBlend(
          GetSystemColor(kColorId_TextfieldDefaultBackground),
          GetSystemColor(kColorId_TextfieldSelectionBackgroundFocused), 0x80);
    case kColorId_ResultsTableSelectedBackground:
      return GetSystemColor(kColorId_TextfieldSelectionBackgroundFocused);
    case kColorId_ResultsTableNormalText:
    case kColorId_ResultsTableHoveredText:
      return GetSystemColor(kColorId_TextfieldDefaultColor);
    case kColorId_ResultsTableSelectedText:
      return GetSystemColor(kColorId_TextfieldSelectionColor);
    case kColorId_ResultsTableNormalDimmedText:
    case kColorId_ResultsTableHoveredDimmedText:
      return color_utils::AlphaBlend(
          GetSystemColor(kColorId_TextfieldDefaultColor),
          GetSystemColor(kColorId_TextfieldDefaultBackground), 0x80);
    case kColorId_ResultsTableSelectedDimmedText:
      return color_utils::AlphaBlend(
          GetSystemColor(kColorId_TextfieldSelectionColor),
          GetSystemColor(kColorId_TextfieldDefaultBackground), 0x80);
    case kColorId_ResultsTableNormalUrl:
    case kColorId_ResultsTableHoveredUrl:
      return NormalURLColor(GetSystemColor(kColorId_TextfieldDefaultColor));

    case kColorId_ResultsTableSelectedUrl:
      return SelectedURLColor(
          GetSystemColor(kColorId_TextfieldSelectionColor),
          GetSystemColor(kColorId_TextfieldSelectionBackgroundFocused));

    case kColorId_ResultsTablePositiveText: {
      return color_utils::GetReadableColor(kPositiveTextColor,
                                           GetBaseColor(GetEntry(), NORMAL));
    }
    case kColorId_ResultsTablePositiveHoveredText: {
      return color_utils::GetReadableColor(kPositiveTextColor,
                                           GetBaseColor(GetEntry(), PRELIGHT));
    }
    case kColorId_ResultsTablePositiveSelectedText: {
      return color_utils::GetReadableColor(kPositiveTextColor,
                                           GetBaseColor(GetEntry(), SELECTED));
    }
    case kColorId_ResultsTableNegativeText: {
      return color_utils::GetReadableColor(kNegativeTextColor,
                                           GetBaseColor(GetEntry(), NORMAL));
    }
    case kColorId_ResultsTableNegativeHoveredText: {
      return color_utils::GetReadableColor(kNegativeTextColor,
                                           GetBaseColor(GetEntry(), PRELIGHT));
    }
    case kColorId_ResultsTableNegativeSelectedText: {
      return color_utils::GetReadableColor(kNegativeTextColor,
                                           GetBaseColor(GetEntry(), SELECTED));
    }

    // Throbber
    case kColorId_ThrobberSpinningColor:
    case kColorId_ThrobberLightColor:
      return GetSystemColor(kColorId_TextfieldSelectionBackgroundFocused);

    case kColorId_ThrobberWaitingColor:
      return color_utils::AlphaBlend(
          GetSystemColor(kColorId_TextfieldSelectionBackgroundFocused),
          GetBgColor(GetWindow(), NORMAL), 0x80);

    // Alert icons
    // Just fall back to the same colors as Aura.
    case kColorId_AlertSeverityLow:
    case kColorId_AlertSeverityMedium:
    case kColorId_AlertSeverityHigh: {
      ui::NativeTheme* fallback_theme =
          color_utils::IsDark(GetTextColor(GetEntry(), NORMAL))
              ? ui::NativeTheme::GetInstanceForNativeUi()
              : ui::NativeThemeDarkAura::instance();
      return fallback_theme->GetSystemColor(color_id);
    }

    case kColorId_NumColors:
      NOTREACHED();
      break;
  }

  return kInvalidColorIdColor;
}

GtkWidget* NativeThemeGtk::GetWindow() const {
  static GtkWidget* fake_window = nullptr;

  if (!fake_window) {
    fake_window = chrome_gtk_frame_new();
    gtk_widget_realize(fake_window);
  }

  return fake_window;
}

GtkWidget* NativeThemeGtk::GetEntry() const {
  static GtkWidget* fake_entry = nullptr;

  if (!fake_entry) {
    fake_entry = gtk_entry_new();

    // The fake entry needs to be in the window so it can be realized so we can
    // use the computed parts of the style.
    gtk_container_add(GTK_CONTAINER(GetWindow()), fake_entry);
    gtk_widget_realize(fake_entry);
  }

  return fake_entry;
}

GtkWidget* NativeThemeGtk::GetLabel() const {
  static GtkWidget* fake_label = nullptr;

  if (!fake_label)
    fake_label = gtk_label_new("");

  return fake_label;
}

GtkWidget* NativeThemeGtk::GetButton() const {
  static GtkWidget* fake_button = nullptr;

  if (!fake_button)
    fake_button = gtk_button_new();

  return fake_button;
}

GtkWidget* NativeThemeGtk::GetBlueButton() const {
  static GtkWidget* fake_bluebutton = nullptr;

  if (!fake_bluebutton) {
    fake_bluebutton = gtk_button_new();
    TurnButtonBlue(fake_bluebutton);
  }

  return fake_bluebutton;
}

GtkWidget* NativeThemeGtk::GetTree() const {
  static GtkWidget* fake_tree = nullptr;

  if (!fake_tree)
    fake_tree = gtk_tree_view_new();

  return fake_tree;
}

GtkWidget* NativeThemeGtk::GetTooltip() const {
  static GtkWidget* fake_tooltip = nullptr;

  if (!fake_tooltip) {
    fake_tooltip = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_widget_set_name(fake_tooltip, "gtk-tooltip");
    gtk_widget_realize(fake_tooltip);
  }

  return fake_tooltip;
}

GtkWidget* NativeThemeGtk::GetMenu() const {
  static GtkWidget* fake_menu = nullptr;

  if (!fake_menu)
    fake_menu = gtk_custom_menu_new();

  return fake_menu;
}

GtkWidget* NativeThemeGtk::GetMenuItem() const {
  static GtkWidget* fake_menu_item = nullptr;

  if (!fake_menu_item) {
    fake_menu_item = gtk_custom_menu_item_new();
    gtk_menu_shell_append(GTK_MENU_SHELL(GetMenu()), fake_menu_item);
  }

  return fake_menu_item;
}

GtkWidget* NativeThemeGtk::GetSeparator() const {
  static GtkWidget* fake_separator = nullptr;

  if (!fake_separator)
    fake_separator = gtk_hseparator_new();

  return fake_separator;
}
#endif

}  // namespace gtk
