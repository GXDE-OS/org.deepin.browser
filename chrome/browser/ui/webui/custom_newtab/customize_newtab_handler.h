// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_WEBUI_COMPONENTS_COMPONENTS_HANDLER_H_
#define CHROME_BROWSER_UI_WEBUI_COMPONENTS_COMPONENTS_HANDLER_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "chrome/browser/ui/search_engines/edit_search_engine_controller.h"
#include "chrome/browser/ui/search_engines/keyword_editor_controller.h"
#include "chrome/browser/ui/tabs/tab_strip_model_observer.h"
#include "content/public/browser/web_ui_message_handler.h"
#include "ui/base/models/table_model_observer.h"

class Profile;

class BrowserList;

namespace base {
class DictionaryValue;
class ListValue;
}  // namespace base

// The handler for Javascript messages for the chrome://components/ page.
class CustomizeNewTabHandler : public content::WebUIMessageHandler,
                               public ui::TableModelObserver {
 public:
  CustomizeNewTabHandler(Profile* profile);
  ~CustomizeNewTabHandler() override;

  // ui::TableModelObserver implementation.
  void OnModelChanged() override;
  void OnItemsChanged(int start, int length) override;
  void OnItemsAdded(int start, int length) override;
  void OnItemsRemoved(int start, int length) override;

  // WebUIMessageHandler implementation.
  void RegisterMessages() override;

  void NotifyNewTabSwitchSearchEngine();

 private:
  // Retrieves all search engines and returns them to WebUI.
  void HandleGetSearchEnginesList(const base::ListValue* args);

  std::unique_ptr<base::DictionaryValue> GetSearchEnginesList();

  // Sets the search engine at the given index to be default. Called from WebUI.
  void HandleSetDefaultSearchEngine(const base::ListValue* args);

  // Returns a dictionary to pass to WebUI representing the given search engine.
  std::unique_ptr<base::DictionaryValue> CreateDictionaryForEngine(
      int index,
      bool is_default);

  // Add two numbers together using integer arithmetic.just for test.just for
  // test.
  void AddNumbers(const base::ListValue* args);

 // Sets the search engine at the given index to be default. Called from WebUI.
  void HandleGetShowSite(const base::ListValue* args);

  void handleGetCustomizeUrlItems(const base::ListValue* args); 
  void handleRestoreCustomizeConfigure(const base::ListValue* args);
  void handleAddCustomizeUrlItems(const base::ListValue* args);
  void handleRemoveCustomizeUrlItems(const base::ListValue* args);
  void handleUpdateCustomizeUrlItems(const base::ListValue* args);
  void handleValidUrl(const base::ListValue * args);
  void notifyCustomizeUrlItemsChange();

 private:
  Profile* const profile_ = nullptr;
  KeywordEditorController list_controller_;
};

#endif  // CHROME_BROWSER_UI_WEBUI_COMPONENTS_COMPONENTS_HANDLER_H_
