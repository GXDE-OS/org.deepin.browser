// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/web_apps/pwa_confirmation_bubble_view.h"

#include "base/strings/string16.h"
#include "base/strings/string_util.h"
#include "chrome/browser/ui/browser_dialogs.h"
#include "chrome/browser/ui/browser_finder.h"
#include "chrome/browser/ui/views/chrome_layout_provider.h"
#include "chrome/browser/ui/views/chrome_typography.h"
#include "chrome/browser/ui/views/frame/browser_view.h"
#include "chrome/browser/ui/views/frame/toolbar_button_provider.h"
#include "chrome/browser/ui/views/page_action/page_action_icon_view.h"
#include "chrome/browser/ui/views/web_apps/web_app_info_image_source.h"
#include "chrome/grit/generated_resources.h"
#include "components/strings/grit/components_strings.h"
#include "components/url_formatter/elide_url.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/gfx/text_elider.h"
#include "ui/views/controls/button/label_button.h"
#include "ui/views/controls/image_view.h"
#include "ui/views/controls/label.h"
#include "ui/views/layout/box_layout.h"

#include "ui/base/resource/resource_bundle.h"
#include "chrome/grit/theme_resources.h"

namespace {

constexpr int kIconSizeInDip = 32;

PWAConfirmationBubbleView* g_bubble_ = nullptr;

bool g_auto_accept_pwa_for_testing = false;

// Returns an ImageView containing the app icon.
std::unique_ptr<views::ImageView> CreateIconView(
    const WebApplicationInfo& web_app_info) {
  constexpr int kIconSize = 48;
  gfx::ImageSkia image(std::make_unique<WebAppInfoImageSource>(
                           kIconSize, web_app_info.icon_bitmaps),
                       gfx::Size(kIconSize, kIconSize));

  auto icon_image_view = std::make_unique<views::ImageView>();
  icon_image_view->SetImage(image);
  return icon_image_view;
}

// Returns a label containing the app name.
std::unique_ptr<views::Label> CreateNameLabel(const base::string16& name) {
  auto name_label = std::make_unique<views::Label>(
      name, CONTEXT_BODY_TEXT_LARGE, views::style::TextStyle::STYLE_PRIMARY);
  name_label->SetHorizontalAlignment(gfx::ALIGN_LEFT);
  name_label->SetElideBehavior(gfx::ELIDE_TAIL);
  // modify by xiaohuyang, Set line height of label to make margins more littler.
  name_label->SetLineHeight(20);
  return name_label;
}

std::unique_ptr<views::Label> CreateOriginLabel(const url::Origin& origin) {
  auto origin_label = std::make_unique<views::Label>(
      FormatOriginForSecurityDisplay(
          origin, url_formatter::SchemeDisplay::OMIT_HTTP_AND_HTTPS),
      CONTEXT_BODY_TEXT_SMALL, views::style::STYLE_SECONDARY);

  origin_label->SetHorizontalAlignment(gfx::ALIGN_LEFT);

  // Elide from head to prevent origin spoofing.
  origin_label->SetElideBehavior(gfx::ELIDE_HEAD);

  // Multiline breaks elision, so explicitly disable multiline.
  origin_label->SetMultiLine(false);
  
  // modify by xiaohuyang, Set line height of label to make margins more littler.
  origin_label->SetLineHeight(20);

  return origin_label;
}

}  // namespace

// static
bool PWAConfirmationBubbleView::IsShowing() {
  return g_bubble_;
}

PWAConfirmationBubbleView::PWAConfirmationBubbleView(
    views::View* anchor_view,
    views::Button* highlight_button,
    std::unique_ptr<WebApplicationInfo> web_app_info,
    chrome::AppInstallationAcceptanceCallback callback)
    : LocationBarBubbleDelegateView(anchor_view, nullptr),
      web_app_info_(std::move(web_app_info)),
      callback_(std::move(callback)) {
  DCHECK(web_app_info_);
  DialogDelegate::SetButtonLabel(
      ui::DIALOG_BUTTON_OK,
      l10n_util::GetStringUTF16(IDS_INSTALL_PWA_BUTTON_LABEL));
  base::TrimWhitespace(web_app_info_->title, base::TRIM_ALL,
                       &web_app_info_->title);
  // PWAs should always be configured to open in a window.
  DCHECK(web_app_info_->open_as_window);

  const ChromeLayoutProvider* layout_provider = ChromeLayoutProvider::Get();

// modify by xiaohuyang, Set the new style of 'PWAConfirmationBubbleView', 2020/12/11 --start
#if 0
  // Use CONTROL insets, because the icon is non-text (see documentation for
  // DialogContentType).
  gfx::Insets margin_insets = layout_provider->GetDialogInsetsForContentType(
      views::CONTROL, views::CONTROL);
  set_margins(margin_insets);

  int icon_label_spacing = layout_provider->GetDistanceMetric(
      views::DISTANCE_RELATED_CONTROL_HORIZONTAL);
  SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kHorizontal, gfx::Insets(),
      icon_label_spacing));

  AddChildView(CreateIconView(*web_app_info_).release());

  views::View* labels = new views::View();
  AddChildView(labels);
  labels->SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical));

  labels->AddChildView(CreateNameLabel(web_app_info_->title).release());
  labels->AddChildView(
      CreateOriginLabel(url::Origin::Create(web_app_info_->app_url)).release());
#else
  /****** New style of 'PWAConfirmationBubbleView' **************
  * ----------------------------------
  * |window icon          close icon|
  * |                               |
  * |            title              |
  * |             name              |
  * |             url               |
  * |                               |
  * |    cancel          install    |
  * ---------------------------------
  * 
  * main-layout                           (content_view_)               Vertical
  * content_view_ layout                  (title, image_name_view_)     Vertical
  * image_name_view_ layout               (image_name_content_view_)    Vertical
  * image_name_content_view_ layout       (name_url_view_)              Horizontal
  * name_url_view_ layout                 (name url)                    Vertical
  * 
  * *************************************************************/
  gfx::Insets margin_insets = layout_provider->GetDialogInsetsForContentType(
      views::CONTROL, views::CONTROL);
  set_margins(gfx::Insets(0, margin_insets.left(), 10, margin_insets.right()));

  int child_spacing = layout_provider->GetDistanceMetric(
      views::DISTANCE_RELATED_CONTROL_HORIZONTAL);
  SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical, gfx::Insets(),
      child_spacing));

  views::View* content_view_ = new views::View();
  const gfx::Insets content_insets =
      layout_provider->GetDialogInsetsForContentType(views::CONTROL, views::CONTROL);
  content_view_->SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical, gfx::Insets(),
      8));

  // title
  auto title_label = std::make_unique<views::Label>(
      l10n_util::GetStringUTF16(IDS_INSTALL_TO_OS_LAUNCH_SURFACE_BUBBLE_TITLE), 
      CONTEXT_BODY_TEXT_LARGE);
  title_label->SetMultiLine(true);
  title_label->SetLineHeight(20);
  title_label->SetFontList(gfx::FontList().DeriveWithWeight(gfx::Font::Weight::BOLD));
  title_label->SetHorizontalAlignment(gfx::ALIGN_CENTER);
  title_label->SizeToFit(
      layout_provider->GetDistanceMetric(
          ChromeDistanceMetric::DISTANCE_BUBBLE_PREFERRED_WIDTH) -
      margins().width());
  content_view_->AddChildView(std::move(title_label));

  // content
  views::View* image_name__view_ = new views::View();
  views::GridLayout* image_name_content_layout 
       = image_name__view_->SetLayoutManager(std::make_unique<views::GridLayout>());
       
  const int column_set_id = 0;
  views::ColumnSet* columns = image_name_content_layout->AddColumnSet(column_set_id);

  const int unrelated_horizontal_spacing = layout_provider->GetDistanceMetric(
          DISTANCE_UNRELATED_CONTROL_HORIZONTAL);
  constexpr int kMinColumnWidth = 120;

  columns->AddPaddingColumn(1.0, unrelated_horizontal_spacing);
  columns->AddColumn(views::GridLayout::LEADING, views::GridLayout::LEADING,
                     views::GridLayout::kFixedSize, views::GridLayout::USE_PREF,
                     0, kMinColumnWidth);
  columns->AddPaddingColumn(1.0, unrelated_horizontal_spacing);

  // content  name / url
  auto name_url_view_ = std::make_unique<views::View>();
  name_url_view_->SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical, gfx::Insets(), 0));
  name_url_view_->AddChildView(CreateNameLabel(web_app_info_->title).release());
  name_url_view_->AddChildView(
      CreateOriginLabel(url::Origin::Create(web_app_info_->app_url)).release());

  image_name_content_layout->StartRow(views::GridLayout::kFixedSize, column_set_id);
  image_name_content_layout->AddView(std::move(name_url_view_), 1.0, 1.0,
                      views::GridLayout::CENTER, views::GridLayout::CENTER);

  content_view_->AddChildView(image_name__view_);

  AddChildView(content_view_);
#endif
  // modify by xiaohuyang, Set the new style of 'PWAConfirmationBubbleView', 2020/12/11 --end

  chrome::RecordDialogCreation(chrome::DialogIdentifier::PWA_CONFIRMATION);

  SetHighlightedButton(highlight_button);
}

PWAConfirmationBubbleView::~PWAConfirmationBubbleView() = default;

bool PWAConfirmationBubbleView::ShouldShowCloseButton() const {
  return true;
}

base::string16 PWAConfirmationBubbleView::GetWindowTitle() const {
  // modify by xiaohuyang, Do not display window title.
#if 0
  return l10n_util::GetStringUTF16(
      IDS_INSTALL_TO_OS_LAUNCH_SURFACE_BUBBLE_TITLE);
#else
  return base::string16();
#endif
}

// add by xiaohuyang, Display window icon.
#if 1
gfx::ImageSkia PWAConfirmationBubbleView::GetWindowIcon() {
  gfx::Size image_size{kIconSizeInDip, kIconSizeInDip};
  gfx::ImageSkia icon;
  if(web_app_info_->icon_bitmaps.empty()){
    icon = *(ui::ResourceBundle::GetSharedInstance().GetImageSkiaNamed(IDR_PERMISSION_PROMPT_BUBBLE_VIEW_ICON));
  } else {
    icon = gfx::ImageSkia(
      std::make_unique<WebAppInfoImageSource>(kIconSizeInDip, web_app_info_->icon_bitmaps),
      image_size);
  }
  return icon;
}
bool PWAConfirmationBubbleView::ShouldShowWindowIcon() const {
  return true;
}
#endif

views::View* PWAConfirmationBubbleView::GetInitiallyFocusedView() {
  return nullptr;
}

void PWAConfirmationBubbleView::WindowClosing() {
  DCHECK_EQ(g_bubble_, this);
  g_bubble_ = nullptr;
  if (callback_) {
    DCHECK(web_app_info_);
    std::move(callback_).Run(false, std::move(web_app_info_));
  }
}

bool PWAConfirmationBubbleView::Accept() {
  DCHECK(web_app_info_);
  std::move(callback_).Run(true, std::move(web_app_info_));
  return true;
}

namespace chrome {

void ShowPWAInstallBubble(content::WebContents* web_contents,
                          std::unique_ptr<WebApplicationInfo> web_app_info,
                          AppInstallationAcceptanceCallback callback) {
  if (g_bubble_)
    return;

  Browser* browser = chrome::FindBrowserWithWebContents(web_contents);
  if (!browser)
    return;

  BrowserView* browser_view = BrowserView::GetBrowserViewForBrowser(browser);
  views::View* anchor_view =
      browser_view->toolbar_button_provider()->GetAnchorView(
          PageActionIconType::kPwaInstall);
  PageActionIconView* icon =
      browser_view->toolbar_button_provider()->GetPageActionIconView(
          PageActionIconType::kPwaInstall);

  g_bubble_ = new PWAConfirmationBubbleView(
      anchor_view, icon, std::move(web_app_info), std::move(callback));

  views::BubbleDialogDelegateView::CreateBubble(g_bubble_)->Show();

  if (g_auto_accept_pwa_for_testing)
    g_bubble_->AcceptDialog();

  if (icon) {
    icon->Update();
    DCHECK(icon->GetVisible());
  }
}

void SetAutoAcceptPWAInstallConfirmationForTesting(bool auto_accept) {
  g_auto_accept_pwa_for_testing = auto_accept;
}

}  // namespace chrome
