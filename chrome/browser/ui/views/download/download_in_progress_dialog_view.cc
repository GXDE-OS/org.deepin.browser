// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/download/download_in_progress_dialog_view.h"

#include "chrome/browser/ui/browser_dialogs.h"
#include "chrome/browser/ui/views/chrome_layout_provider.h"
#include "chrome/browser/ui/views/chrome_typography.h"
#include "chrome/grit/chromium_strings.h"
#include "chrome/grit/generated_resources.h"
#include "components/constrained_window/constrained_window_views.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/gfx/geometry/size.h"
#include "ui/views/controls/label.h"
#include "ui/views/layout/fill_layout.h"

#include "ui/views/controls/textfield/textfield.h"
#include "chrome/browser/ui/views/textfield_layout.h"
#include "ui/base/resource/resource_bundle.h"
#include "chrome/grit/theme_resources.h"

#ifdef USE_UNIONTECH_NPAPI
#include "chrome/browser/ui/views/frame/browser_view.h"
#include "ui/aura/window.h"
#endif

// static
void DownloadInProgressDialogView::Show(
    gfx::NativeWindow parent,
    int download_count,
    Browser::DownloadCloseType dialog_type,
    bool app_modal,
    const base::Callback<void(bool)>& callback) {
  DownloadInProgressDialogView* window = new DownloadInProgressDialogView(
      download_count, dialog_type, app_modal, callback);

#ifdef USE_UNIONTECH_NPAPI
  views::Widget* widget = constrained_window::CreateBrowserModalDialogViews(window, parent);
  BrowserView *browser_view = (BrowserView *)(parent->GetNativeWindowProperty("__BROWSER_VIEW__"));
  if (browser_view) {
    widget->GetNpapiPuginMask()->AddObserver(browser_view->GetNpapiPluginMaskObserver(widget));

    for (auto* observer_ : browser_view->GetNpapiPluginMaskObserverForChildFrame(widget)) {
      if (observer_) {
        widget->GetNpapiPuginMask()->AddObserver(observer_);
      }
    }
  }
  widget->Show();
#else
  constrained_window::CreateBrowserModalDialogViews(window, parent)->Show();
#endif
}

DownloadInProgressDialogView::DownloadInProgressDialogView(
    int download_count,
    Browser::DownloadCloseType dialog_type,
    bool app_modal,
    const base::Callback<void(bool)>& callback)
    : download_count_(download_count),
      app_modal_(app_modal),
      callback_(callback) {
  DialogDelegate::SetDefaultButton(ui::DIALOG_BUTTON_OK);
 
  DialogDelegate::SetButtonLabel(
      ui::DIALOG_BUTTON_OK,
      l10n_util::GetStringUTF16(IDS_ABANDON_DOWNLOAD_DIALOG_EXIT_BUTTON));
  DialogDelegate::SetButtonLabel(
      ui::DIALOG_BUTTON_CANCEL,
      l10n_util::GetStringUTF16(IDS_ABANDON_DOWNLOAD_DIALOG_CONTINUE_BUTTON));
  SetLayoutManager(std::make_unique<views::FillLayout>());
  // modify by xiaohuyang, Set the content margins of 'DownloadInProgressDialogView',  2020/10/27 --start
#if 0
  set_margins(ChromeLayoutProvider::Get()->GetDialogInsetsForContentType(
      views::TEXT, views::TEXT));
#else
  constexpr int kContentMarginTop = 0;
  constexpr int kContentMarginBottom = 10;
  const gfx::Insets margin_inset = ChromeLayoutProvider::Get()->GetDialogInsetsForContentType(
      views::TEXT, views::TEXT);
  set_margins(gfx::Insets(kContentMarginTop, margin_inset.left(), kContentMarginBottom, margin_inset.right()));
#endif
  // modify by xiaohuyang, Set the content margins of 'DownloadInProgressDialogView',  2020/10/27 --end

  auto run_callback = [](DownloadInProgressDialogView* dialog, bool accept) {
    // Note that accepting this dialog means "cancel the download", while cancel
    // means "continue the download".
    dialog->callback_.Run(accept);
  };
  DialogDelegate::SetAcceptCallback(
      base::BindOnce(run_callback, base::Unretained(this), true));
  DialogDelegate::SetCancelCallback(
      base::BindOnce(run_callback, base::Unretained(this), false));
  DialogDelegate::SetCloseCallback(
      base::BindOnce(run_callback, base::Unretained(this), false));

  int message_id = 0;
  switch (dialog_type) {
    case Browser::DownloadCloseType::kLastWindowInIncognitoProfile:
      message_id = IDS_ABANDON_DOWNLOAD_DIALOG_INCOGNITO_MESSAGE;
      break;
    case Browser::DownloadCloseType::kLastWindowInGuestSession:
      message_id = IDS_ABANDON_DOWNLOAD_DIALOG_GUEST_MESSAGE;
      break;
    case Browser::DownloadCloseType::kBrowserShutdown:
      message_id = IDS_ABANDON_DOWNLOAD_DIALOG_BROWSER_MESSAGE;
      break;
    case Browser::DownloadCloseType::kOk:
      // This dialog should have been created within the same thread invocation
      // as the original test, so it's never ok to close.
      NOTREACHED();
      break;
  }
  // modify by hanll, 修改下载弹框样式, 2020/10/10, start
#if 0
  auto message_label = std::make_unique<views::Label>(
      l10n_util::GetStringUTF16(message_id), CONTEXT_BODY_TEXT_LARGE,
      views::style::STYLE_SECONDARY);
  message_label->SetMultiLine(true);
  message_label->SetHorizontalAlignment(gfx::ALIGN_LEFT);
  AddChildView(message_label.release());
#else
  //SetLayoutManager(std::make_unique<views::FillLayout>());
  auto contents_view = std::make_unique<views::View>();
  views::GridLayout* layout = contents_view->SetLayoutManager(
      std::make_unique<views::GridLayout>());

  constexpr int kColumnId = 0;
  ConfigureTextfieldStack(layout, kColumnId);

  //标题
  //int row_height = views::LayoutProvider::GetControlHeightForFont(
  //     kFontContext, kFontStyle, textfield_ptr->GetDefaultFontList());
  layout->StartRow(views::GridLayout::kFixedSize, kColumnId, 24);
  views::Label* headlabel = layout->AddView(std::make_unique<views::Label>(
      l10n_util::GetPluralStringFUTF16(IDS_ABANDON_DOWNLOAD_DIALOG_TITLE,download_count_), 
      CONTEXT_BODY_TEXT_LARGE,views::style::STYLE_PRIMARY));

  headlabel->SetFontList(gfx::FontList().DeriveWithWeight(gfx::Font::Weight::BOLD));

  //message
  layout->StartRow(views::GridLayout::kFixedSize, kColumnId, 24);
  views::Label* messagelabel = layout->AddView(std::make_unique<views::Label>(l10n_util::GetStringUTF16(message_id), 
      CONTEXT_BODY_TEXT_SMALL,views::style::STYLE_SECONDARY));

  AddChildView(std::move(contents_view));

#endif
  // modify by hanll, 修改下载弹框样式, 2020/10/10, end

  chrome::RecordDialogCreation(chrome::DialogIdentifier::DOWNLOAD_IN_PROGRESS);
}

DownloadInProgressDialogView::~DownloadInProgressDialogView() = default;

gfx::Size DownloadInProgressDialogView::CalculatePreferredSize() const {
  const int width = ChromeLayoutProvider::Get()->GetDistanceMetric(
                        DISTANCE_MODAL_DIALOG_PREFERRED_WIDTH) -
                    margins().width();
  return gfx::Size(width, GetHeightForWidth(width));
}

ui::ModalType DownloadInProgressDialogView::GetModalType() const {
  return app_modal_ ? ui::MODAL_TYPE_SYSTEM : ui::MODAL_TYPE_WINDOW;
}

bool DownloadInProgressDialogView::ShouldShowCloseButton() const {
  return true;
}

base::string16 DownloadInProgressDialogView::GetWindowTitle() const {
  return base::string16();
  return l10n_util::GetPluralStringFUTF16(IDS_ABANDON_DOWNLOAD_DIALOG_TITLE,
                                          download_count_);
}

gfx::ImageSkia DownloadInProgressDialogView::GetWindowIcon() {
  // modify by xiaohuyang, Set the window icon of 'DownloadInProgressDialogView'.
  return *(ui::ResourceBundle::GetSharedInstance().GetImageSkiaNamed(IDR_PERMISSION_PROMPT_BUBBLE_VIEW_ICON));
}

bool DownloadInProgressDialogView::ShouldShowWindowIcon() const {
  return true;
}

BEGIN_METADATA(DownloadInProgressDialogView)
METADATA_PARENT_CLASS(views::DialogDelegateView);
END_METADATA()
