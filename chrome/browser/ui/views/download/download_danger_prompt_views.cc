// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/strings/utf_string_conversions.h"
#include "chrome/browser/download/download_danger_prompt.h"

#include "base/compiler_specific.h"
#include "chrome/browser/download/download_stats.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/safe_browsing/advanced_protection_status_manager.h"
#include "chrome/browser/safe_browsing/advanced_protection_status_manager_factory.h"
#include "chrome/browser/ui/bookmarks/bookmark_editor.h"
#include "chrome/browser/ui/browser_dialogs.h"
#include "chrome/browser/ui/views/chrome_layout_provider.h"
#include "chrome/grit/chromium_strings.h"
#include "chrome/grit/generated_resources.h"
#include "components/constrained_window/constrained_window_views.h"
#include "components/download/public/common/download_danger_type.h"
#include "components/download/public/common/download_item.h"
#include "components/strings/grit/components_strings.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/download_item_utils.h"
#include "content/public/browser/web_contents.h"
#include "ui/base/buildflags.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/views/controls/label.h"
#include "ui/views/layout/fill_layout.h"
#include "ui/views/window/dialog_delegate.h"
#include "url/gurl.h"
#include "chrome/browser/ui/views/chrome_typography.h"
#include "ui/views/layout/box_layout.h"
#include "chrome/grit/theme_resources.h"

using safe_browsing::ClientSafeBrowsingReportRequest;

namespace {

  // modify by baohaifeng, modify DownloadDangerPrompt UI . 2021/3/19  --start
  constexpr int kIconSizeInDip = 32;
  // modify by baohaifeng, modify DownloadDangerPrompt UI . 2021/3/19  --end

// Views-specific implementation of download danger prompt dialog. We use this
// class rather than a TabModalConfirmDialog so that we can use custom
// formatting on the text in the body of the dialog.
class DownloadDangerPromptViews : public DownloadDangerPrompt,
                                  public download::DownloadItem::Observer,
                                  public views::DialogDelegateView {
 public:
  DownloadDangerPromptViews(download::DownloadItem* item,
                            Profile* profile,
                            bool show_context,
                            const OnDone& done);
  ~DownloadDangerPromptViews() override;

  // DownloadDangerPrompt:
  void InvokeActionForTesting(Action action) override;

  // views::DialogDelegateView:
  gfx::Size CalculatePreferredSize() const override;
  base::string16 GetWindowTitle() const override;
  ui::ModalType GetModalType() const override;

  // download::DownloadItem::Observer:
  void OnDownloadUpdated(download::DownloadItem* download) override;

  //modify by baohaifeng, modify DownloadDangerPrompt UI . 2021/3/19  --start
  gfx::ImageSkia GetWindowIcon() override;
  bool ShouldShowWindowIcon() const override;
  //modify by baohaifeng, modify DownloadDangerPrompt UI . 2021/3/19  --end


 private:
  base::string16 GetMessageBody() const;
  void RunDone(Action action);

  download::DownloadItem* download_;
  Profile* profile_;
  // If show_context_ is true, this is a download confirmation dialog by
  // download API, otherwise it is download recovery dialog from a regular
  // download.
  const bool show_context_;
  OnDone done_;
};

DownloadDangerPromptViews::DownloadDangerPromptViews(
    download::DownloadItem* item,
    Profile* profile,
    bool show_context,
    const OnDone& done)
    : download_(item),
      profile_(profile),
      show_context_(show_context),
      done_(done) {
  // Note that this prompt is asking whether to cancel a dangerous download, so
  // the accept path is titled "Cancel".
  DialogDelegate::SetButtonLabel(ui::DIALOG_BUTTON_OK,
                                   l10n_util::GetStringUTF16(IDS_CANCEL));
  DialogDelegate::SetButtonLabel(
      ui::DIALOG_BUTTON_CANCEL,
      show_context_ ? l10n_util::GetStringUTF16(IDS_CONFIRM_DOWNLOAD)
                    : l10n_util::GetStringUTF16(IDS_CONFIRM_DOWNLOAD_AGAIN));

  auto make_done_callback = [&](DownloadDangerPrompt::Action action) {
    return base::BindOnce(&DownloadDangerPromptViews::RunDone,
                          base::Unretained(this), action);
  };

  // Note that the presentational concept of "Accept/Cancel" is inverted from
  // the model's concept of ACCEPT/CANCEL. In the UI, the safe path is "Accept"
  // and the dangerous path is "Cancel".
  DialogDelegate::SetAcceptCallback(make_done_callback(CANCEL));
  DialogDelegate::SetCancelCallback(make_done_callback(ACCEPT));
  DialogDelegate::SetCloseCallback(make_done_callback(DISMISS));

  download_->AddObserver(this);

  set_margins(ChromeLayoutProvider::Get()->GetDialogInsetsForContentType(
      views::TEXT, views::TEXT));
  SetLayoutManager(std::make_unique<views::FillLayout>());

  views::Label* message_body_label = new views::Label(GetMessageBody());
  message_body_label->SetMultiLine(true);
  //modify by baohaifeng, modify DownloadDangerPrompt UI . 2021/3/19  --start
  message_body_label->SetHorizontalAlignment(gfx::ALIGN_CENTER);
  //modify by baohaifeng, modify DownloadDangerPrompt UI . 2021/3/19  --end
  message_body_label->SetAllowCharacterBreak(true);

  //modify by baohaifeng, modify DownloadDangerPrompt UI . 2021/3/19  --start
  const ChromeLayoutProvider* layout_provider = ChromeLayoutProvider::Get();

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
      l10n_util::GetStringUTF16(IDS_CONFIRM_KEEP_DANGEROUS_DOWNLOAD_TITLE), 
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
  content_view_->AddChildView(message_body_label);
  AddChildView(content_view_);
  //modify by baohaifeng, modify DownloadDangerPrompt UI . 2021/3/19  --start

  RecordOpenedDangerousConfirmDialog(download_->GetDangerType());

  chrome::RecordDialogCreation(
      chrome::DialogIdentifier::DOWNLOAD_DANGER_PROMPT);
}

DownloadDangerPromptViews::~DownloadDangerPromptViews() {
  if (download_)
    download_->RemoveObserver(this);
}

// DownloadDangerPrompt methods:
void DownloadDangerPromptViews::InvokeActionForTesting(Action action) {
  switch (action) {
    case ACCEPT:
      // This inversion is intentional.
      Cancel();
      break;

    case DISMISS:
      Close();
      break;

    case CANCEL:
      Accept();
      break;

    default:
      NOTREACHED();
      break;
  }
}

//modify by baohaifeng, modify DownloadDangerPrompt UI . 2021/3/19  --start
// views::DialogDelegate methods:
base::string16 DownloadDangerPromptViews::GetWindowTitle() const { 
#if UNUSED
  if (show_context_ || !download_)  // |download_| may be null in tests.
    return l10n_util::GetStringUTF16(IDS_CONFIRM_KEEP_DANGEROUS_DOWNLOAD_TITLE);
  switch (download_->GetDangerType()) {
    case download::DOWNLOAD_DANGER_TYPE_DANGEROUS_URL:
    case download::DOWNLOAD_DANGER_TYPE_DANGEROUS_CONTENT:
    case download::DOWNLOAD_DANGER_TYPE_DANGEROUS_HOST:
    case download::DOWNLOAD_DANGER_TYPE_POTENTIALLY_UNWANTED:
      return l10n_util::GetStringUTF16(IDS_KEEP_DANGEROUS_DOWNLOAD_TITLE);
    case download::DOWNLOAD_DANGER_TYPE_UNCOMMON_CONTENT:
      return l10n_util::GetStringUTF16(IDS_KEEP_UNCOMMON_DOWNLOAD_TITLE);
    default: {
      return l10n_util::GetStringUTF16(
          IDS_CONFIRM_KEEP_DANGEROUS_DOWNLOAD_TITLE);
    }
  }
#else
  return base::string16();
#endif
}

//Display window icon.  
gfx::ImageSkia DownloadDangerPromptViews::GetWindowIcon() {
  gfx::Size image_size{kIconSizeInDip, kIconSizeInDip};
  gfx::ImageSkia icon;
  icon = *(ui::ResourceBundle::GetSharedInstance().GetImageSkiaNamed(IDR_PERMISSION_PROMPT_BUBBLE_VIEW_ICON));
  return icon;
}
bool DownloadDangerPromptViews::ShouldShowWindowIcon() const {
  return true;
}
//modify by baohaifeng, modify DownloadDangerPrompt UI . 2021/3/19  --end

ui::ModalType DownloadDangerPromptViews::GetModalType() const {
  return ui::MODAL_TYPE_CHILD;
}

// download::DownloadItem::Observer:
void DownloadDangerPromptViews::OnDownloadUpdated(
    download::DownloadItem* download) {
  // If the download is nolonger dangerous (accepted externally) or the download
  // is in a terminal state, then the download danger prompt is no longer
  // necessary.
  if (!download_->IsDangerous() || download_->IsDone()) {
    RunDone(DISMISS);
    Cancel();
  }
}

gfx::Size DownloadDangerPromptViews::CalculatePreferredSize() const {
  int preferred_width = ChromeLayoutProvider::Get()->GetDistanceMetric(
                            DISTANCE_BUBBLE_PREFERRED_WIDTH) -
                        margins().width();
  return gfx::Size(preferred_width, GetHeightForWidth(preferred_width));
}

base::string16 DownloadDangerPromptViews::GetMessageBody() const {
  if (show_context_) {
    switch (download_->GetDangerType()) {
      case download::DOWNLOAD_DANGER_TYPE_DANGEROUS_FILE: {
        return l10n_util::GetStringFUTF16(
            IDS_PROMPT_DANGEROUS_DOWNLOAD,
            download_->GetFileNameToReportUser().LossyDisplayName());
      }
      case download::DOWNLOAD_DANGER_TYPE_DANGEROUS_URL:  // Fall through
      case download::DOWNLOAD_DANGER_TYPE_DANGEROUS_CONTENT:
      case download::DOWNLOAD_DANGER_TYPE_DANGEROUS_HOST: {
        return l10n_util::GetStringFUTF16(
            IDS_PROMPT_MALICIOUS_DOWNLOAD_CONTENT,
            download_->GetFileNameToReportUser().LossyDisplayName());
      }
      case download::DOWNLOAD_DANGER_TYPE_UNCOMMON_CONTENT: {
        if (safe_browsing::AdvancedProtectionStatusManagerFactory::
                GetForProfile(profile_)
                    ->IsUnderAdvancedProtection()) {
          return l10n_util::GetStringFUTF16(
              IDS_PROMPT_UNCOMMON_DOWNLOAD_CONTENT_IN_ADVANCED_PROTECTION,
              download_->GetFileNameToReportUser().LossyDisplayName());
        } else {
          return l10n_util::GetStringFUTF16(
              IDS_PROMPT_UNCOMMON_DOWNLOAD_CONTENT,
              download_->GetFileNameToReportUser().LossyDisplayName());
        }
      }
      case download::DOWNLOAD_DANGER_TYPE_POTENTIALLY_UNWANTED: {
        return l10n_util::GetStringFUTF16(
            IDS_PROMPT_DOWNLOAD_CHANGES_SETTINGS,
            download_->GetFileNameToReportUser().LossyDisplayName());
      }
      case download::DOWNLOAD_DANGER_TYPE_BLOCKED_UNSUPPORTED_FILETYPE:
      case download::DOWNLOAD_DANGER_TYPE_PROMPT_FOR_SCANNING:
      case download::DOWNLOAD_DANGER_TYPE_SENSITIVE_CONTENT_WARNING:
      case download::DOWNLOAD_DANGER_TYPE_SENSITIVE_CONTENT_BLOCK:
      case download::DOWNLOAD_DANGER_TYPE_DEEP_SCANNED_SAFE:
      case download::DOWNLOAD_DANGER_TYPE_DEEP_SCANNED_OPENED_DANGEROUS:
      case download::DOWNLOAD_DANGER_TYPE_BLOCKED_TOO_LARGE:
      case download::DOWNLOAD_DANGER_TYPE_BLOCKED_PASSWORD_PROTECTED:
      case download::DOWNLOAD_DANGER_TYPE_ASYNC_SCANNING:
      case download::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS:
      case download::DOWNLOAD_DANGER_TYPE_MAYBE_DANGEROUS_CONTENT:
      case download::DOWNLOAD_DANGER_TYPE_USER_VALIDATED:
      case download::DOWNLOAD_DANGER_TYPE_WHITELISTED_BY_POLICY:
      case download::DOWNLOAD_DANGER_TYPE_MAX: {
        break;
      }
    }
  } else {
    // If we're mixed content, we show that warning first.
    if (download_->IsMixedContent()) {
      return l10n_util::GetStringFUTF16(
          IDS_PROMPT_CONFIRM_MIXED_CONTENT_DOWNLOAD,
          download_->GetFileNameToReportUser().LossyDisplayName());
    }
    switch (download_->GetDangerType()) {
      case download::DOWNLOAD_DANGER_TYPE_DANGEROUS_URL:
      case download::DOWNLOAD_DANGER_TYPE_DANGEROUS_CONTENT:
      case download::DOWNLOAD_DANGER_TYPE_DANGEROUS_HOST:
      case download::DOWNLOAD_DANGER_TYPE_POTENTIALLY_UNWANTED:
      case download::DOWNLOAD_DANGER_TYPE_UNCOMMON_CONTENT: {
        return l10n_util::GetStringUTF16(
            IDS_PROMPT_CONFIRM_KEEP_MALICIOUS_DOWNLOAD_BODY);
      }
      default: {
        return l10n_util::GetStringUTF16(
            IDS_PROMPT_CONFIRM_KEEP_DANGEROUS_DOWNLOAD);
      }
    }
  }
  NOTREACHED();
  return base::string16();
}

void DownloadDangerPromptViews::RunDone(Action action) {
  // Invoking the callback can cause the download item state to change or cause
  // the window to close, and |callback| refers to a member variable.
  OnDone done = done_;
  done_.Reset();
  if (download_ != NULL) {
    // If this download is no longer dangerous, is already canceled or
    // completed, don't send any report.
    if (download_->IsDangerous() && !download_->IsDone()) {
      const bool accept = action == DownloadDangerPrompt::ACCEPT;
      RecordDownloadDangerPrompt(accept, *download_);
      if (!download_->GetURL().is_empty() &&
          !content::DownloadItemUtils::GetBrowserContext(download_)
               ->IsOffTheRecord()) {
        ClientSafeBrowsingReportRequest::ReportType report_type
            = show_context_ ?
                ClientSafeBrowsingReportRequest::DANGEROUS_DOWNLOAD_BY_API :
                ClientSafeBrowsingReportRequest::DANGEROUS_DOWNLOAD_RECOVERY;
        SendSafeBrowsingDownloadReport(report_type, accept, *download_);
      }
    }
    download_->RemoveObserver(this);
    download_ = NULL;
  }
  if (!done.is_null())
    done.Run(action);
}

}  // namespace

// static
DownloadDangerPrompt* DownloadDangerPrompt::Create(
    download::DownloadItem* item,
    content::WebContents* web_contents,
    bool show_context,
    const OnDone& done) {
  Profile* profile =
      Profile::FromBrowserContext(web_contents->GetBrowserContext());
  DownloadDangerPromptViews* download_danger_prompt =
      new DownloadDangerPromptViews(item, profile, show_context, done);
  constrained_window::ShowWebModalDialogViews(download_danger_prompt,
                                              web_contents);
  return download_danger_prompt;
}
