// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_WEBUI_SETTINGS_USBKEY_DRIVER_HANDLER_H_
#define CHROME_BROWSER_UI_WEBUI_SETTINGS_USBKEY_DRIVER_HANDLER_H_
#ifndef OPENSSL_NO_GMTLS

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
//#include "chrome/browser/ui/search_engines/edit_search_engine_controller.h"
//#include "chrome/browser/ui/search_engines/keyword_editor_controller.h"
#include "content/public/browser/web_ui_message_handler.h"
#include "components/prefs/pref_change_registrar.h"
#include "ui/base/models/table_model_observer.h"

#include "ui/shell_dialogs/select_file_dialog.h"

class Profile;
class BrowserList;

namespace base {
class DictionaryValue;
class ListValue;
}

namespace settings {
  class SettingsPageUIHandler;
}
namespace usbkeydriver_manager {

class USBKeyDriverHandler : public content::WebUIMessageHandler,
                            public ui::SelectFileDialog::Listener {
 public:
  explicit USBKeyDriverHandler(Profile* profile);
  ~USBKeyDriverHandler();

  // ui::TableModelObserver implementation.
  //void OnModelChanged() override;
  //void OnItemsChanged(int start, int length) override;
  //void OnItemsAdded(int start, int length) override;
  //void OnItemsRemoved(int start, int length) override;

  // EditSearchEngineControllerDelegate implementation.
  //void OnEditedKeyword(TemplateURL* template_url,
   //                    const base::string16& title,
   //                    const base::string16& keyword,
   //                    const std::string& url) override;

   //SettingsPageUIHandler implementation.
  void RegisterMessages() override;
  void OnJavascriptAllowed() override;
  void OnJavascriptDisallowed() override;

 private:
  // Retrieves all search engines and returns them to WebUI.
  void HandleGetUSBKeyDriversList(const base::ListValue* args);

  base::DictionaryValue* GetUSBKeyDriversList();

  // Removes the search engine at the given index. Called from WebUI.
  void HandleRemoveUSBKeyDriver(const base::ListValue* args);

  // Starts an edit session for the search engine at the given index. If the
  // index is -1, starts editing a new search engine instead of an existing one.
  // Called from WebUI.
  void HandleUSBKeyDriverEditStarted(const base::ListValue* args);

  // Validates the given search engine values, and reports the results back
  // to WebUI. Called from WebUI.
  void HandleValidateUSBKeyDriverInput(const base::ListValue* args);

  // Checks whether the given user input field (searchEngine, keyword, queryUrl)
  // is populated with a valid value.
  bool CheckFieldValidity(const std::string& field_name,
                          const std::string& field_value);

  // Called when an edit is canceled.
  // Called from WebUI.
  void HandleUSBKeyDriverEditCancelled(const base::ListValue* args);

  // Called when an edit is finished and should be saved.
  // Called from WebUI.
  void HandleUSBKeyDriverEditCompleted(const base::ListValue* args);

  // Returns a dictionary to pass to WebUI representing the given search engine.
  std::unique_ptr<base::DictionaryValue> CreateDictionaryForUSBKeyDriver(
      int index,
      bool is_default);

  // Returns a dictionary to pass to WebUI representing the extension.
  //base::DictionaryValue* CreateDictionaryForExtension(
  //    const extensions::Extension& extension);

  //void NotifyNewTabSwitchSearchEngine();

  void HandleUSBKeyDriverSelectLocation(const base::ListValue* args);

  //Check the driver path valid
  bool IsDriverPathValid(const std::string& driver_path) const;

  // SelectFileDialog::Listener implementation.
  void FileSelected(const base::FilePath& path,
                    int index,
                    void* params) override;

  Profile* const profile_;

  int m_deviceid{0};
  //KeywordEditorController list_controller_;
  //std::unique_ptr<EditSearchEngineController> edit_controller_;
  PrefChangeRegistrar pref_change_registrar_;
  base::WeakPtrFactory<USBKeyDriverHandler> weak_ptr_factory_{this};

  scoped_refptr<ui::SelectFileDialog> select_folder_dialog_;

  DISALLOW_COPY_AND_ASSIGN(USBKeyDriverHandler);
};

}  // namespace usbkeydriver_manager
#endif //#OPENSSL_NO_GMTLS
#endif  // CHROME_BROWSER_UI_WEBUI_SETTINGS_USBKEY_DRIVER_HANDLER_H_
