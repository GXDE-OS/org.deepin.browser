// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/external_protocol_dialog.h"

#include <utility>

#include "base/strings/string_util.h"
#include "chrome/browser/external_protocol/external_protocol_handler.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/shell_integration.h"
#include "chrome/browser/tab_contents/tab_util.h"
#include "chrome/browser/ui/browser_dialogs.h"
#include "chrome/browser/ui/views/chrome_layout_provider.h"
#include "chrome/browser/ui/views/chrome_typography.h"
#include "chrome/common/pref_names.h"
#include "chrome/grit/chromium_strings.h"
#include "chrome/grit/generated_resources.h"
#include "components/constrained_window/constrained_window_views.h"
#include "components/prefs/pref_service.h"
#include "components/url_formatter/elide_url.h"
#include "content/public/browser/web_contents.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/gfx/text_elider.h"
#include "ui/views/controls/label.h"
// #include "ui/views/controls/message_box_view.h"
#include "ui/views/layout/fill_layout.h"
#include "ui/views/widget/widget.h"

#include "ui/base/resource/resource_bundle.h"
#include "chrome/grit/theme_resources.h"
#include "ui/views/layout/box_layout.h"
#include "ui/views/controls/message_box_view_xdg.h"

using content::WebContents;

namespace {

base::string16 GetMessageTextForOrigin(
    const base::Optional<url::Origin>& origin) {
  if (!origin || origin->opaque())
    return l10n_util::GetStringUTF16(IDS_EXTERNAL_PROTOCOL_MESSAGE);
  return l10n_util::GetStringFUTF16(
      IDS_EXTERNAL_PROTOCOL_MESSAGE_WITH_INITIATING_ORIGIN,
      url_formatter::FormatOriginForSecurityDisplay(*origin));
}

}  // namespace

// static
void ExternalProtocolHandler::RunExternalProtocolDialog(
    const GURL& url,
    WebContents* web_contents,
    ui::PageTransition ignored_page_transition,
    bool ignored_has_user_gesture,
    const base::Optional<url::Origin>& initiating_origin) {
  DCHECK(web_contents);

  base::string16 program_name =
      shell_integration::GetApplicationNameForProtocol(url);
  if (program_name.empty()) {
    // ShellExecute won't do anything. Don't bother warning the user.
    return;
  }

  // Windowing system takes ownership.
  new ExternalProtocolDialog(web_contents, url, program_name,
                             initiating_origin);
}

ExternalProtocolDialog::ExternalProtocolDialog(
    WebContents* web_contents,
    const GURL& url,
    const base::string16& program_name,
    const base::Optional<url::Origin>& initiating_origin)
    : content::WebContentsObserver(web_contents),
      url_(url),
      program_name_(program_name),
      initiating_origin_(initiating_origin) {
  // modify by xiaohuyang, Set default button.   --2020/11/24
#if 0
  DialogDelegate::SetDefaultButton(ui::DIALOG_BUTTON_CANCEL);
#else
  DialogDelegate::SetDefaultButton(ui::DIALOG_BUTTON_OK);
#endif
  DialogDelegate::SetButtonLabel(
      ui::DIALOG_BUTTON_OK,
      l10n_util::GetStringFUTF16(IDS_EXTERNAL_PROTOCOL_OK_BUTTON_TEXT,
                                 program_name_));
  DialogDelegate::SetButtonLabel(
      ui::DIALOG_BUTTON_CANCEL,
      l10n_util::GetStringUTF16(IDS_EXTERNAL_PROTOCOL_CANCEL_BUTTON_TEXT));

  DialogDelegate::SetAcceptCallback(base::BindOnce(
      &ExternalProtocolDialog::OnDialogAccepted, base::Unretained(this)));
  DialogDelegate::SetCancelCallback(base::BindOnce(
      &ExternalProtocolHandler::RecordHandleStateMetrics,
      false /* checkbox_selected */, ExternalProtocolHandler::BLOCK));
  DialogDelegate::SetCloseCallback(base::BindOnce(
      &ExternalProtocolHandler::RecordHandleStateMetrics,
      false /* checkbox_selected */, ExternalProtocolHandler::BLOCK));

  // modify by xiaohuyang, Set new layout and style of this view, 2020/11/24 --start
  // Created a 'content_view_' to include 'title' and 'message', then add 'content_view_' as child of this view.
#if 0
  views::MessageBoxView::InitParams params(
      GetMessageTextForOrigin(initiating_origin_));
  message_box_view_ = new views::MessageBoxView(params);

  ChromeLayoutProvider* provider = ChromeLayoutProvider::Get();
  set_margins(
      provider->GetDialogInsetsForContentType(views::TEXT, views::TEXT));

  SetLayoutManager(std::make_unique<views::FillLayout>());

#else
  ChromeLayoutProvider* provider = ChromeLayoutProvider::Get();
  SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical, gfx::Insets(),
      provider->GetDistanceMetric(views::DISTANCE_RELATED_LABEL_HORIZONTAL)));
  content_view_ = new views::View();
  const gfx::Insets content_insets =
      provider->GetDialogInsetsForContentType(views::CONTROL, views::CONTROL);
  content_view_->SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical, gfx::Insets(),
      0));

  // title 
  constexpr int kMaxCommandCharsToDisplay = 32;
  base::string16 elided;
  base::string16 title_text;
  gfx::ElideString(program_name_, kMaxCommandCharsToDisplay, &elided);
  title_text = l10n_util::GetStringFUTF16(IDS_EXTERNAL_PROTOCOL_TITLE, elided);

  auto title_label = std::make_unique<views::Label>(title_text, CONTEXT_BODY_TEXT_LARGE);
  title_label->SetMultiLine(true);
  title_label->SetLineHeight(20);
  title_label->SetFontList(gfx::FontList().DeriveWithWeight(gfx::Font::Weight::BOLD));
  title_label->SetHorizontalAlignment(gfx::ALIGN_CENTER);
  title_label->SizeToFit(
      provider->GetDistanceMetric(
          ChromeDistanceMetric::DISTANCE_BUBBLE_PREFERRED_WIDTH) -
      margins().width());
  content_view_->AddChildView(std::move(title_label));

  // message
  views::XdgMessageBoxView::InitParams params(
      GetMessageTextForOrigin(initiating_origin_));
  message_box_view_ = new views::XdgMessageBoxView(params);
  message_box_view_->SetPreferredSize(gfx::Size(320, 20));
  content_view_->AddChildView(std::move(message_box_view_));

  set_margins(gfx::Insets(0, 20, 0, 20));
#endif
  // modify by xiaohuyang, Set new layout and style of this view, 2020/11/24 --end

  Profile* profile =
      Profile::FromBrowserContext(web_contents->GetBrowserContext());
  if (profile->GetPrefs()->GetBoolean(
          prefs::kExternalProtocolDialogShowAlwaysOpenCheckbox)) {
    ShowRememberSelectionCheckbox();
  }
  constrained_window::ShowWebModalDialogViews(this, web_contents);
  chrome::RecordDialogCreation(chrome::DialogIdentifier::EXTERNAL_PROTOCOL);
}

ExternalProtocolDialog::~ExternalProtocolDialog() = default;

gfx::Size ExternalProtocolDialog::CalculatePreferredSize() const {
  // modify by xiaohuyang, Set the preferred size of this view.    2020/11/24
#if 0
  constexpr int kDialogContentWidth = 400;
#else
  constexpr int kDialogContentWidth = 385;
#endif
  return gfx::Size(kDialogContentWidth, GetHeightForWidth(kDialogContentWidth));
}

bool ExternalProtocolDialog::ShouldShowCloseButton() const {
  // modify by xiaohuyang, Display close button.    2020/11/24
#if 0
  return false;
#else
  return true;
#endif
}

base::string16 ExternalProtocolDialog::GetWindowTitle() const {
  // modify by xiaohuyang, Do not display window title.    2020/11/24
#if 0
  constexpr int kMaxCommandCharsToDisplay = 32;
  base::string16 elided;
  gfx::ElideString(program_name_, kMaxCommandCharsToDisplay, &elided);
  return l10n_util::GetStringFUTF16(IDS_EXTERNAL_PROTOCOL_TITLE, elided);
#else
  return base::string16();
#endif
}

void ExternalProtocolDialog::OnDialogAccepted() {
  const bool remember = message_box_view_->IsCheckBoxSelected();
  ExternalProtocolHandler::RecordHandleStateMetrics(
      remember, ExternalProtocolHandler::DONT_BLOCK);

  if (!web_contents()) {
    // Dialog outlasted the WebContents.
    return;
  }

  if (remember) {
    Profile* profile =
        Profile::FromBrowserContext(web_contents()->GetBrowserContext());

    ExternalProtocolHandler::SetBlockState(
        url_.scheme(), ExternalProtocolHandler::DONT_BLOCK, profile);
  }

  ExternalProtocolHandler::LaunchUrlWithoutSecurityCheck(url_, web_contents());
}

views::View* ExternalProtocolDialog::GetContentsView() {
  // modify by xiaohuyang, Respace 'content_view_' with 'message_box_view_' and add it as child view.    2020/11/24
#if 0
  return message_box_view_;
#else
  return content_view_;
#endif
}

ui::ModalType ExternalProtocolDialog::GetModalType() const {
  return ui::MODAL_TYPE_CHILD;
}

views::Widget* ExternalProtocolDialog::GetWidget() {
  return message_box_view_->GetWidget();
}

const views::Widget* ExternalProtocolDialog::GetWidget() const {
  return message_box_view_->GetWidget();
}

// modify by xiaohuyang, Display window icon.    2020/11/24
#if 1
gfx::ImageSkia ExternalProtocolDialog::GetWindowIcon() {
  return *(ui::ResourceBundle::GetSharedInstance().GetImageSkiaNamed(IDR_PERMISSION_PROMPT_BUBBLE_VIEW_ICON));
}
bool ExternalProtocolDialog::ShouldShowWindowIcon() const {
  return true;
}
#endif

void ExternalProtocolDialog::ShowRememberSelectionCheckbox() {
  message_box_view_->SetCheckBoxLabel(
      l10n_util::GetStringUTF16(IDS_EXTERNAL_PROTOCOL_CHECKBOX_TEXT));
}

void ExternalProtocolDialog::SetRememberSelectionCheckboxCheckedForTesting(
    bool checked) {
  if (!message_box_view_->HasCheckBox())
    ShowRememberSelectionCheckbox();
  message_box_view_->SetCheckBoxSelected(checked);
}
