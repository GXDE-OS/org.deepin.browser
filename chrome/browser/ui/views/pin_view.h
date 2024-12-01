// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_PIN_VIEW_H_
#define CHROME_BROWSER_UI_VIEWS_PIN_VIEW_H_
#ifndef OPENSSL_NO_GMTLS
#include <vector>

#include "base/macros.h"
#include "chrome/browser/ui/task_manager/task_manager_table_model.h"
//#include "ui/base/models/simple_menu_model.h"
#include "ui/base/models/table_model.h"
#include "ui/views/context_menu_controller.h"
#include "ui/views/controls/menu/menu_runner.h"
#include "ui/views/controls/table/table_grouper.h"
#include "ui/views/controls/table/table_view_observer.h"
#include "ui/views/controls/textfield/textfield.h"
#include "ui/views/controls/label.h"
#include "ui/views/window/dialog_delegate.h"
#include "content/public/browser/client_certificate_delegate.h"
#include "content/public/browser/content_browser_client.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_contents_observer.h"

class Browser;
class skfmodule;

namespace views {
class TableView;
class View;
}  // namespace views

namespace task_manager1 {

// The new task manager UI container.
class PinView : public views::DialogDelegateView {
 public:
  ~PinView() override;

  static base::OnceClosure Show(net::SSLCertRequestInfo* certrequestinfo,content::WebContents* web_contents,
      std::unique_ptr<content::ClientCertificateDelegate> delegate,
      skfmodule * in_skf_module,
      X509_NAME * in_issuer);

  // views::View:
  gfx::Size CalculatePreferredSize() const override;
  gfx::Size GetMinimumSize() const override;
  gfx::Size GetMaximumSize() const override;
  // bool AcceleratorPressed(const ui::Accelerator& accelerator) override;

  // views::DialogDelegateView:
  views::View* GetInitiallyFocusedView() override;
  bool CanResize() const override;
  bool CanMaximize() const override;
  bool CanMinimize() const override;
  // bool ExecuteWindowsCommand(int command_id) override;
  // base::string16 GetWindowTitle() const override;
  gfx::ImageSkia GetWindowIcon() override;
  bool ShouldShowWindowIcon() const override;
  std::string GetWindowName() const override;
  bool Accept() override;
  void DeleteDelegate() override;
  void CloseDialog();
  void OnCancel();
  base::OnceClosure GetCancellationCallback();
  // bool IsDialogButtonEnabled(ui::DialogButton button) const override;
  // void WindowClosing() override;

  void SetDelegate(std::unique_ptr<content::ClientCertificateDelegate> d) {
    delegate_ = std::move(d);
  }
  std::unique_ptr<content::ClientCertificateDelegate> delegate_;
  // void SetParams(void* param);
  // void SetWebContentGetter(base::Callback<content::WebContents*(void)> wc_getter);
  ui::ModalType GetModalType() const override;
 //private:

  PinView();

  // Creates the child controls.
  void Init();
  void SetSkfModule(skfmodule * skf_module){
    skf_module_ = skf_module;
  }
  void SetIssuer(X509_NAME * issuer){
    issuer_=issuer;
  }

  skfmodule * skf_module_;
  X509_NAME * issuer_;

  base::WeakPtrFactory<PinView> weak_factory_{this};
  // 输入框
  views::Textfield* name_field_;
  // 错误提示框
  views::Label* errorlabel_ = nullptr;
  // std::string host_port_name_;
  // content::WebContents* current_webcontent_ = nullptr;
  // views::Label* promptlabel_ = nullptr;
  DISALLOW_COPY_AND_ASSIGN(PinView);
  
};

}  // namespace task_manager
#endif
#endif  // CHROME_BROWSER_UI_VIEWS_PIN_VIEW_H_
