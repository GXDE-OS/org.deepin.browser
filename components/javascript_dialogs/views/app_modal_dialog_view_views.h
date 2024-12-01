// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_JAVASCRIPT_DIALOGS_VIEWS_APP_MODAL_DIALOG_VIEW_VIEWS_H_
#define COMPONENTS_JAVASCRIPT_DIALOGS_VIEWS_APP_MODAL_DIALOG_VIEW_VIEWS_H_

#include <memory>

#include "base/macros.h"
#include "components/javascript_dialogs/app_modal_dialog_view.h"
#include "ui/views/window/dialog_delegate.h"

//modify by xiaohuyang, Handle the task of #82352.
#include "ui/views/controls/button/button.h"

namespace views {
class MessageBoxView;
//modify by xiaohuyang, Handle the task of #82352.
class LabelButton;
}

namespace javascript_dialogs {

class AppModalDialogController;

//modify by xiaohuyang, Handle the task of #82352.
#if UNUSED
class AppModalDialogViewViews : public AppModalDialogView,
                                public views::DialogDelegateView {//},
                                //public views::DialogDelegate {
#else
class AppModalDialogViewViews : public AppModalDialogView,
                                public views::DialogDelegateView,
                                public views::ButtonListener {//},
                                //public views::DialogDelegate {
#endif
 public:
  explicit AppModalDialogViewViews(AppModalDialogController* controller);
  ~AppModalDialogViewViews() override;

  // AppModalDialogView:
  void ShowAppModalDialog() override;
  void ActivateAppModalDialog() override;
  void CloseAppModalDialog() override;
  void AcceptAppModalDialog() override;
  void CancelAppModalDialog() override;
  bool IsShowing() const override;

  // views::DialogDelegate:
  base::string16 GetWindowTitle() const override;
  void DeleteDelegate() override;
  bool Cancel() override;
  bool Accept() override;
  ui::ModalType GetModalType() const override;
  views::View* GetContentsView() override;
  views::View* GetInitiallyFocusedView() override;
  views::Widget* GetWidget() override;
  const views::Widget* GetWidget() const override;
  bool ShouldShowCloseButton() const override;
  void WindowClosing() override;

  // views::DialogDelegateView:
  gfx::ImageSkia GetWindowIcon() override;
  bool ShouldShowWindowIcon() const override;

  //modify by xiaohuyang, Handle the task of #82352.
  void ButtonPressed(views::Button* sender, const ui::Event& event) override;
  void CloseDialog();

 private:
  std::unique_ptr<AppModalDialogController> controller_;

  // The message box view whose commands we handle.
  views::MessageBoxView* message_box_view_;

  //modify by xiaohuyang, Handle the task of #82352.
  views::LabelButton* cancel_button_;

  DISALLOW_COPY_AND_ASSIGN(AppModalDialogViewViews);
};

}  // namespace javascript_dialogs

#endif  // COMPONENTS_JAVASCRIPT_DIALOGS_VIEWS_APP_MODAL_DIALOG_VIEW_VIEWS_H_
