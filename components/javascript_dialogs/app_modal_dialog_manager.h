// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_JAVASCRIPT_DIALOGS_APP_MODAL_DIALOG_MANAGER_H_
#define COMPONENTS_JAVASCRIPT_DIALOGS_APP_MODAL_DIALOG_MANAGER_H_

#include <memory>

#include "base/callback.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/singleton.h"
#include "components/javascript_dialogs/app_modal_dialog_controller.h"
#include "content/public/browser/javascript_dialog_manager.h"

namespace javascript_dialogs {

class ExtensionsClient;
class AppModalViewFactory;

class AppModalDialogManager : public content::JavaScriptDialogManager {
 public:
  // A factory method to create and returns a platform-specific dialog class.
  // The returned object should own itself.
  using AppModalViewFactory =
      base::RepeatingCallback<AppModalDialogView*(AppModalDialogController*)>;

  static AppModalDialogManager* GetInstance();

  // Sets the AppModalViewFactory used to create platform specific
  // dialog window instances.
  void SetNativeDialogFactory(AppModalViewFactory factory);

  AppModalViewFactory* view_factory() { return &view_factory_; }

  // JavaScript dialogs may be opened by an extensions/app, thus they need
  // access to extensions functionality. This sets a client interface to
  // access //extensions.
  void SetExtensionsClient(std::unique_ptr<ExtensionsClient> extensions_client);

  // Gets the title for a dialog.
  base::string16 GetTitle(content::WebContents* web_contents,
                          const GURL& alerting_frame_url);

  // Displays a dialog asking the user if they want to leave a page. Displays
  // a different message if the site is in an app window.
  void RunBeforeUnloadDialogWithOptions(
      content::WebContents* web_contents,
      content::RenderFrameHost* render_frame_host,
      bool is_reload,
      bool is_app,
      DialogClosedCallback callback);

  //modify by xiaohuyang, Handle the task of #82352.
  void RunBeforeUnloadDialogWithOptionsForBankAndIRC(
      content::WebContents* web_contents,
      content::RenderFrameHost* render_frame_host,
      bool is_reload,
      bool is_tab_close,
      const base::string16& bank,
      const base::string16& message,
      bool is_app,
      DialogClosedCallback callback);

  // content::JavaScriptDialogManager:
  void RunJavaScriptDialog(content::WebContents* web_contents,
                           content::RenderFrameHost* render_frame_host,
                           content::JavaScriptDialogType dialog_type,
                           const base::string16& message_text,
                           const base::string16& default_prompt_text,
                           DialogClosedCallback callback,
                           bool* did_suppress_message) override;
  void RunBeforeUnloadDialog(content::WebContents* web_contents,
                             content::RenderFrameHost* render_frame_host,
                             bool is_reload,
                             DialogClosedCallback callback) override;
  //modify by xiaohuyang, Handle the task of #82352.
  void RunBeforeUnloadDialogForBankAndIRC(content::WebContents* web_contents,
                                          content::RenderFrameHost* render_frame_host,
                                          bool is_reload,
                                          bool is_tab_close,
                                          const base::string16& bank,
                                          const base::string16& message,
                                          DialogClosedCallback callback) override;
  bool HandleJavaScriptDialog(content::WebContents* web_contents,
                              bool accept,
                              const base::string16* prompt_override) override;
  void CancelDialogs(content::WebContents* web_contents,
                     bool reset_state) override;

 private:
  FRIEND_TEST_ALL_PREFIXES(AppModalDialogManagerTest, GetTitle);
  friend struct base::DefaultSingletonTraits<AppModalDialogManager>;

  AppModalDialogManager();
  ~AppModalDialogManager() override;

  // Wrapper around OnDialogClosed; logs UMA stats before continuing on.
  void OnBeforeUnloadDialogClosed(content::WebContents* web_contents,
                                  DialogClosedCallback callback,
                                  bool success,
                                  const base::string16& user_input);

  // Wrapper around a DialogClosedCallback so that we can intercept it before
  // passing it onto the original callback.
  void OnDialogClosed(content::WebContents* web_contents,
                      DialogClosedCallback callback,
                      bool success,
                      const base::string16& user_input);

  static base::string16 GetTitleImpl(const GURL& parent_frame_url,
                                     const GURL& alerting_frame_url);

  // Mapping between the WebContents and their extra data. The key
  // is a void* because the pointer is just a cookie and is never dereferenced.
  AppModalDialogController::ExtraDataMap javascript_dialog_extra_data_;

  AppModalViewFactory view_factory_;
  std::unique_ptr<ExtensionsClient> extensions_client_;

  DISALLOW_COPY_AND_ASSIGN(AppModalDialogManager);
};

}  // namespace javascript_dialogs

#endif  // COMPONENTS_JAVASCRIPT_DIALOGS_APP_MODAL_DIALOG_MANAGER_H_
