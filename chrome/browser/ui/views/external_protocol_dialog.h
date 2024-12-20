// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_EXTERNAL_PROTOCOL_DIALOG_H_
#define CHROME_BROWSER_UI_VIEWS_EXTERNAL_PROTOCOL_DIALOG_H_

#include "base/macros.h"
#include "content/public/browser/web_contents_observer.h"
#include "ui/views/window/dialog_delegate.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace content {
class WebContents;
}

namespace test {
class ExternalProtocolDialogTestApi;
}

namespace views {
//modify by xiaohuyang, Respace 'XdgMessageBoxView' with 'MessageBoxView'.
#if 0
class MessageBoxView;
#else
class XdgMessageBoxView;
#endif
}

class ExternalProtocolDialog : public views::DialogDelegateView,
                               public content::WebContentsObserver {
 public:
  // Show by calling ExternalProtocolHandler::RunExternalProtocolDialog().
  ExternalProtocolDialog(content::WebContents* web_contents,
                         const GURL& url,
                         const base::string16& program_name,
                         const base::Optional<url::Origin>& initiating_origin);
  ~ExternalProtocolDialog() override;

  // views::DialogDelegateView:
  gfx::Size CalculatePreferredSize() const override;
  bool ShouldShowCloseButton() const override;
  base::string16 GetWindowTitle() const override;
  views::View* GetContentsView() override;
  ui::ModalType GetModalType() const override;
  views::Widget* GetWidget() override;
  const views::Widget* GetWidget() const override;

  //add by xiaohuyang, Display window icon.    --2020/11/24
#if 1
  gfx::ImageSkia GetWindowIcon() override;
  bool ShouldShowWindowIcon() const override;
#endif

 private:
  friend class test::ExternalProtocolDialogTestApi;

  void ShowRememberSelectionCheckbox();
  void SetRememberSelectionCheckboxCheckedForTesting(bool checked);
  void OnDialogAccepted();

  const GURL url_;
  const base::string16 program_name_;
  const base::Optional<url::Origin> initiating_origin_;
  
  //modify by xiaohuyang, Respace 'XdgMessageBoxView' with 'MessageBoxView' and Use 'content_view_' to include the child view.    --2020/11/24
#if 0
  // The message box whose commands we handle.
  views::MessageBoxView* message_box_view_;
#else
  views::XdgMessageBoxView* message_box_view_;
  views::View* content_view_ = nullptr;
#endif

  DISALLOW_COPY_AND_ASSIGN(ExternalProtocolDialog);
};

#endif  // CHROME_BROWSER_UI_VIEWS_EXTERNAL_PROTOCOL_DIALOG_H_
