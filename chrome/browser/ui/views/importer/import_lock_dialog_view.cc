// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/importer/import_lock_dialog_view.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/metrics/user_metrics.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "chrome/browser/importer/importer_lock_dialog.h"
#include "chrome/browser/ui/browser_dialogs.h"
#include "chrome/browser/ui/views/chrome_layout_provider.h"
#include "chrome/grit/chromium_strings.h"
#include "chrome/grit/generated_resources.h"
#include "chrome/grit/locale_settings.h"
#include "ui/base/buildflags.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/views/border.h"
#include "ui/views/controls/label.h"
#include "ui/views/layout/fill_layout.h"
#include "ui/views/widget/widget.h"

#include "ui/base/resource/resource_bundle.h"
#include "chrome/grit/theme_resources.h"
#include "chrome/browser/ui/views/textfield_layout.h"

using base::UserMetricsAction;

namespace importer {

void ShowImportLockDialog(gfx::NativeWindow parent,
                          const base::Callback<void(bool)>& callback) {
  ImportLockDialogView::Show(parent, callback);
}

}  // namespace importer

// static
void ImportLockDialogView::Show(gfx::NativeWindow parent,
                                const base::Callback<void(bool)>& callback) {
  //views::DialogDelegate::CreateDialogWidget(
  //    new ImportLockDialogView(callback), NULL, NULL)->Show();
  views::DialogDelegate::CreateDialogWidget(
    new ImportLockDialogView(callback), NULL, parent)->Show();
  base::RecordAction(UserMetricsAction("ImportLockDialogView_Shown"));
}

ImportLockDialogView::ImportLockDialogView(
    const base::Callback<void(bool)>& callback)
    : callback_(callback) {
  DialogDelegate::SetButtonLabel(
      ui::DIALOG_BUTTON_OK, l10n_util::GetStringUTF16(IDS_IMPORTER_LOCK_OK));
#if 0
  SetLayoutManager(std::make_unique<views::FillLayout>());
  views::Label* description_label =
      new views::Label(l10n_util::GetStringUTF16(IDS_IMPORTER_LOCK_TEXT));
  description_label->SetBorder(views::CreateEmptyBorder(
      ChromeLayoutProvider::Get()->GetDialogInsetsForContentType(views::TEXT,
                                                                 views::TEXT)));
  description_label->SetMultiLine(true);
  description_label->SetHorizontalAlignment(gfx::ALIGN_LEFT);
  AddChildView(description_label);
#else
  // modify by hanll,修改原来的布局，添加个标题, 2020/10/28, start
  SetLayoutManager(std::make_unique<views::FillLayout>());
  auto contents_view = std::make_unique<views::View>();
  views::GridLayout* layout = contents_view->SetLayoutManager(
      std::make_unique<views::GridLayout>());

  constexpr int kColumnId = 0;
  ConfigureTextfieldStack(layout, kColumnId);

  //增加标题
  AddTitleRow(layout,l10n_util::GetStringUTF16(IDS_IMPORTER_LOCK_TITLE),kColumnId);
  //增加Message(即描述)
  AddMessageRow(layout,l10n_util::GetStringUTF16(IDS_IMPORTER_LOCK_TEXT),kColumnId);
  
  AddChildView(std::move(contents_view));
  // modify by hanll,修改原来的布局，添加个标题, 2020/10/28, end
#endif
  chrome::RecordDialogCreation(chrome::DialogIdentifier::IMPORT_LOCK);
}

ImportLockDialogView::~ImportLockDialogView() {
}

gfx::Size ImportLockDialogView::CalculatePreferredSize() const {
  const int width = ChromeLayoutProvider::Get()->GetDistanceMetric(
      DISTANCE_MODAL_DIALOG_PREFERRED_WIDTH);
  return gfx::Size(width,60);  //60:content中高度
  return gfx::Size(width, GetHeightForWidth(width));
}

base::string16 ImportLockDialogView::GetWindowTitle() const {
  return base::string16();
  return l10n_util::GetStringUTF16(IDS_IMPORTER_LOCK_TITLE);
}

bool ImportLockDialogView::Accept() {
  if (callback_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback_, true));
  }
  return true;
}

bool ImportLockDialogView::Cancel() {
  if (callback_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback_, false));
  }
  return true;
}

bool ImportLockDialogView::ShouldShowCloseButton() const {
  return true;
}

ui::ModalType ImportLockDialogView::GetModalType() const {
  return ui::MODAL_TYPE_CHILD;
}

gfx::ImageSkia ImportLockDialogView::GetWindowIcon() {
  return *(ui::ResourceBundle::GetSharedInstance().GetImageSkiaNamed(IDR_PERMISSION_PROMPT_BUBBLE_VIEW_ICON));
}

// Ensure the display of the icon
bool ImportLockDialogView::ShouldShowWindowIcon() const {
  return true;
}

