// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/custom_newtab/customize_newtab_handler.h"

#include "base/bind.h"
#include "base/json/json_file_value_serializer.h"
#include "base/json/json_reader.h"
#include "base/json/json_string_value_serializer.h"
#include "base/json/json_writer.h"
#include "base/values.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/search_engines/ui_thread_search_terms_data.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_list.h"
#include "chrome/browser/ui/search_engines/template_url_table_model.h"
#include "chrome/browser/ui/tabs/tab_strip_model.h"
#include "chrome/common/url_constants.h"
#include "chrome/grit/generated_resources.h"
#include "components/search_engines/template_url.h"
#include "components/update_client/crx_update_item.h"
#include "content/public/browser/web_contents.h"
#include "ui/base/l10n/l10n_util.h"

#include "base/linux_util.h"

#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "base/hash/md5.h"
#include "base/files/file_path.h"
#include "ui/base/l10n/l10n_util.h"

#include "chrome/grit/generated_resources.h"
#include "chrome/common/chrome_paths.h"
#include "chrome/browser/ui/webui/settings_utils.h"

#include "uos/customize_new_tabs/newtabs_thread_manager.h"

CustomizeNewTabHandler::CustomizeNewTabHandler(Profile* profile)
    : profile_(profile), list_controller_(profile_) {}
CustomizeNewTabHandler::~CustomizeNewTabHandler() {}

void CustomizeNewTabHandler::RegisterMessages() {
  web_ui()->RegisterMessageCallback(
      "GetSearchEnginesList",
      base::BindRepeating(&CustomizeNewTabHandler::HandleGetSearchEnginesList,
                          base::Unretained(this)));

  web_ui()->RegisterMessageCallback(
      "setDefaultSearchEngine",
      base::BindRepeating(&CustomizeNewTabHandler::HandleSetDefaultSearchEngine,
                          base::Unretained(this)));
  
  web_ui()->RegisterMessageCallback(
      "getShowSite",
      base::BindRepeating(&CustomizeNewTabHandler::HandleGetShowSite,
                          base::Unretained(this)));

  web_ui()->RegisterMessageCallback("getCustomizeUrlItems", 
      base::BindRepeating(&CustomizeNewTabHandler::handleGetCustomizeUrlItems,
                          base::Unretained(this)));


  web_ui()->RegisterMessageCallback("restoreCustomizeConfigure", 
      base::BindRepeating(&CustomizeNewTabHandler::handleRestoreCustomizeConfigure,
                          base::Unretained(this)));

  web_ui()->RegisterMessageCallback("addCustomizeUrlItems", 
      base::BindRepeating(&CustomizeNewTabHandler::handleAddCustomizeUrlItems,
                          base::Unretained(this)));


  web_ui()->RegisterMessageCallback("removeCustomizeUrlItems", 
      base::BindRepeating(&CustomizeNewTabHandler::handleRemoveCustomizeUrlItems,
                          base::Unretained(this)));

  web_ui()->RegisterMessageCallback("updateCustomizeUrlItems", 
      base::BindRepeating(&CustomizeNewTabHandler::handleUpdateCustomizeUrlItems,
                          base::Unretained(this)));

  web_ui()->RegisterMessageCallback("validUrl", 
      base::BindRepeating(&CustomizeNewTabHandler::handleValidUrl,
                          base::Unretained(this)));
}

void CustomizeNewTabHandler::OnModelChanged() {
  LOG(INFO) << "CustomizeNewTabHandler::OnModelChanged";
  AllowJavascript();
  FireWebUIListener("search-engines-changed", *GetSearchEnginesList());

  NotifyNewTabSwitchSearchEngine();
}

void CustomizeNewTabHandler::NotifyNewTabSwitchSearchEngine() {
  int browserCount = BrowserList::GetInstance()->size();
  LOG(INFO) << "BrowserList::GetInstance().size():" << browserCount;

  for (int bi = 0; bi < browserCount; bi++) {
    Browser* bw = BrowserList::GetInstance()->get(bi);
    Profile* p = bw->profile();
    if (bw && (!p->IsIncognitoProfile())) {
      TabStripModel* tsm = bw->tab_strip_model();
      int tsmCount = tsm->count();
      for (int ti = 0; ti < tsmCount; ti++) {
        content::WebContents* wc = tsm->GetWebContentsAt(ti);
        if (wc) {
          // wc->GetWebUI()
          GURL url = wc->GetURL();
          if (url.host_piece() == chrome::kChromeUINewTabHost) {
            LOG(INFO) << "wc:" << ti;
            std::unique_ptr<base::DictionaryValue> result0 = GetSearchEnginesList(); //.get();
            std::string strjson;
            JSONStringValueSerializer serializer(&strjson);
            serializer.set_pretty_print(true);
            bool bret = serializer.Serialize(*(result0.get()));
            LOG(INFO) << "bret:" << bret;
            // LOG(ERROR) << "strjson:" << strjson;
            base::Value v(strjson);

            // modify by xiaohuyang, fix bug#85105,  2021/07/12
            // You can refer to the NotifyNewTabSwitchSearchEngine method in the chrome/browser/ui/webui/settings/search_engines_handler.cc file. 
            // The judgment on the pointer is missing here.
            if(wc->GetWebUI())
              wc->GetWebUI()->CallJavascriptFunctionUnsafe("uos_newtab.addResult", v);
          }
          LOG(INFO) << "ti:" << ti;
        }
      }
    }
  }

  LOG(INFO) << "BrowserList::GetInstance().size():" << browserCount;
}

void CustomizeNewTabHandler::OnItemsChanged(int start, int length) {
  OnModelChanged();
  LOG(INFO) << "CustomizeNewTabHandler::OnItemsChanged";
}

void CustomizeNewTabHandler::OnItemsAdded(int start, int length) {
  OnModelChanged();
  LOG(INFO) << "CustomizeNewTabHandler::OnItemsAdded";
}

void CustomizeNewTabHandler::OnItemsRemoved(int start, int length) {
  OnModelChanged();
  LOG(INFO) << "CustomizeNewTabHandler::OnItemsRemoved";
}

void CustomizeNewTabHandler::AddNumbers(const base::ListValue* args) {
  LOG(INFO) << "11";

  int term1, term2;
  if (!args->GetInteger(0, &term1) || !args->GetInteger(1, &term2))
    return;
  // base::FundamentalValue result(term1 + term2);
  // CallJavascriptFunction("hello_world.addResult", result);
  LOG(INFO) << "22";
  int re = term1 + term2;
  base::Value result(re);
  // m_webui->
  // CallJavascriptFunction("hello_world.addResult", result);
  web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.addResult", result);
  LOG(INFO) << "33";
}

void CustomizeNewTabHandler::HandleGetSearchEnginesList(
    const base::ListValue* args) {
  // CHECK_EQ(1U, args->GetSize());
  // const base::Value* callback_id;
  // CHECK(args->Get(0, &callback_id));
  // AllowJavascript();
  // ResolveJavascriptCallback(*callback_id, *GetSearchEnginesList());

  // base::Value* result = GetSearchEnginesList().get();
  // int i=1,j=2;
  // int r = i+j;
  // base::Value result(r);
  // web_ui()->CallJavascriptFunctionUnsafe("hello_world.addResult", *result);

  std::unique_ptr<base::DictionaryValue> result0 = GetSearchEnginesList();
  std::string strjson;
  JSONStringValueSerializer serializer(&strjson);
  serializer.set_pretty_print(true);
  bool bret = serializer.Serialize(*(result0.get()));
  LOG(INFO) << "bret:" << bret;
  // LOG(ERROR) << "strjson:" << strjson;
  base::Value v(strjson);

  web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.addResult", v);
}

std::unique_ptr<base::DictionaryValue>
CustomizeNewTabHandler::GetSearchEnginesList() {
  // Find the default engine.
  const TemplateURL* default_engine =
      list_controller_.GetDefaultSearchProvider();
  int default_index =
      list_controller_.table_model()->IndexOfTemplateURL(default_engine);

  // Build the first list (default search engines).
  auto defaults = std::make_unique<base::ListValue>();
  int last_default_engine_index =
      list_controller_.table_model()->last_search_engine_index();

  // Sanity check for https://crbug.com/781703.
  CHECK_GE(last_default_engine_index, 0);

  for (int i = 0; i < last_default_engine_index; ++i) {
    // Third argument is false, as the engine is not from an extension.

    LOG(INFO) << "last_default_engine_index:" << last_default_engine_index;
    defaults->Append(CreateDictionaryForEngine(i, i == default_index));
  }

  // Build the second list (other search engines).
  auto others = std::make_unique<base::ListValue>();
  int last_other_engine_index = list_controller_.table_model()->last_other_engine_index();

  // Sanity check for https://crbug.com/781703.
  CHECK_LE(last_default_engine_index, last_other_engine_index);

  for (int i = std::max(last_default_engine_index, 0);
       i < last_other_engine_index; ++i) {
      LOG(INFO) << "last_other_engine_index:" << last_other_engine_index;

      others->Append(CreateDictionaryForEngine(i, i == default_index));
  }

  // Build the third list (omnibox extensions).
  auto extensions = std::make_unique<base::ListValue>();
  int engine_count = list_controller_.table_model()->RowCount();

  // Sanity check for https://crbug.com/781703.
  CHECK_LE(last_other_engine_index, engine_count);

  for (int i = std::max(last_other_engine_index, 0); i < engine_count; ++i) {
      LOG(INFO) << "engine_count:" << engine_count;
      extensions->Append(CreateDictionaryForEngine(i, i == default_index));
  }

  auto search_engines_info = std::make_unique<base::DictionaryValue>();
  search_engines_info->Set("defaults", std::move(defaults));
  search_engines_info->Set("others", std::move(others));
  search_engines_info->Set("extensions", std::move(extensions));
  return search_engines_info;
}

std::unique_ptr<base::DictionaryValue>
CustomizeNewTabHandler::CreateDictionaryForEngine(int index, bool is_default) {
  TemplateURLTableModel* table_model = list_controller_.table_model();
  const TemplateURL* template_url = list_controller_.GetTemplateURL(index);

  // Sanity check for https://crbug.com/781703.
  CHECK_GE(index, 0);
  CHECK_LT(index, table_model->RowCount());
  CHECK(template_url);

  // The items which are to be written into |dict| are also described in
  // chrome/browser/resources/settings/search_engines_page/
  // in @typedef for SearchEngine. Please update it whenever you add or remove
  // any keys here.
  auto dict = std::make_unique<base::DictionaryValue>();
  dict->SetInteger("id", template_url->id());
  dict->SetString("name", template_url->short_name());
  dict->SetString("displayName",
                  table_model->GetText(
                      index, IDS_SEARCH_ENGINES_EDITOR_DESCRIPTION_COLUMN));

  LOG(INFO) << "displayname:"
            << table_model->GetText(
                   index, IDS_SEARCH_ENGINES_EDITOR_DESCRIPTION_COLUMN)
            << "is_defualt:" << is_default;

  dict->SetString(
      "keyword",
      table_model->GetText(index, IDS_SEARCH_ENGINES_EDITOR_KEYWORD_COLUMN));
  //Profile* profile = Profile::FromWebUI(web_ui());
  dict->SetString(
      "url", template_url->url_ref().DisplayURL(UIThreadSearchTermsData()));
  dict->SetBoolean("urlLocked", template_url->prepopulate_id() > 0);
  GURL icon_url = template_url->favicon_url();
  if (icon_url.is_valid())
    dict->SetString("iconURL", icon_url.spec());
  dict->SetInteger("modelIndex", index);

  dict->SetBoolean("canBeRemoved", list_controller_.CanRemove(template_url));
  dict->SetBoolean("canBeDefault",
                   list_controller_.CanMakeDefault(template_url));
  dict->SetBoolean("default", is_default);
  dict->SetBoolean("canBeEdited", list_controller_.CanEdit(template_url));
  TemplateURL::Type type = template_url->type();
  dict->SetBoolean("isOmniboxExtension",
                   type == TemplateURL::OMNIBOX_API_EXTENSION);
  /*if (type == TemplateURL::NORMAL_CONTROLLED_BY_EXTENSION ||
    type == TemplateURL::OMNIBOX_API_EXTENSION) {
  const extensions::Extension* extension =
      extensions::ExtensionRegistry::Get(profile)->GetExtensionById(
          template_url->GetExtensionId(),
          extensions::ExtensionRegistry::EVERYTHING);
  if (extension) {
    std::unique_ptr<base::DictionaryValue> ext_info =
        extensions::util::GetExtensionInfo(extension);
    ext_info->SetBoolean("canBeDisabled",
                         !extensions::ExtensionSystem::Get(profile)
                              ->management_policy()
                              ->MustRemainEnabled(extension, nullptr));
    dict->Set("extension", std::move(ext_info));
  }
}*/

  return dict;
}

void CustomizeNewTabHandler::HandleSetDefaultSearchEngine(
    const base::ListValue* args) {
  int index;
  /*if (!ExtractIntegerValue(args, &index)) {
  NOTREACHED();
  return;
  }*/
  LOG(INFO) << "HandleSetDefaultSearchEngine0";

  if (!args->GetInteger(0, &index))
    return;

  if (index < 0 || index >= list_controller_.table_model()->RowCount())
    return;

  list_controller_.MakeDefaultTemplateURL(index);

  LOG(INFO) << "HandleSetDefaultSearchEngine1";

  OnItemsChanged(0, 0);

  // base::RecordAction(base::UserMetricsAction("Options_SearchEngineSetDefault"));
}

void CustomizeNewTabHandler::HandleGetShowSite(
    const base::ListValue* args) {

  LOG(INFO) << "-----HandleGetShowSite0--------";
  std::string osversion = base::GetUosEdition();
  bool bret = true;
  LOG(INFO)<<"-------base::GetUosEdition-----"<<base::GetUosEdition();
  if(osversion.compare("Community") == 0)
    bret = false;

  base::Value v(bret);
  web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.getShowSite", v);
  LOG(INFO) << "------HandleGetShowSite10----------";
}

bool Value2String(base::Value & in_v, std::string & out) {
  std::string ret = "";
  JSONStringValueSerializer _serializer(&ret);
  if (_serializer.Serialize(in_v)) {
    out = ret;
    return true;
  }
  return false;
}

class CustomizeNewTabParam {
public:
  CustomizeNewTabParam();
  void parserFromListValue(const base::ListValue* args);
  bool is_valid_param();
  virtual std::string err_info_json();

public:
  std::string sessionID;
};

CustomizeNewTabParam::CustomizeNewTabParam() {
  sessionID = "";
}

bool CustomizeNewTabParam::is_valid_param() {
  return !sessionID.empty();
}

void CustomizeNewTabParam::parserFromListValue(const base::ListValue* args) {
  if (!args) {
    return;
  }
  std::string str_json;
  if (args->GetString(0, &str_json)) {
    auto result = base::JSONReader::Read(str_json);
    if (result.has_value()) {
      if (result.value().is_dict()) {
        for (auto _item: result.value().DictItems()) {
          if (_item.first == "sessionID") {
            if (_item.second.is_string()) {
              sessionID = _item.second.GetString();
            }
            break;
          }
        }
      }
    }
  }
  return ;
}

std::string CustomizeNewTabParam::err_info_json() {
  if (sessionID.empty()) {
      base::DictionaryValue ret_val;
       ret_val.SetBoolean("sucess", false);
       ret_val.SetString("err", "参数错误");
       std::string payload;
       Value2String(ret_val, payload);
       return payload;
  }
  return "";
}

class CustomizeNewTabParam_Add:public CustomizeNewTabParam {
public:
  CustomizeNewTabParam_Add();
  void parserFromListValue(const base::ListValue* args);
  bool is_valid_param();

public:
  int index = -1;
  std::string title = "";
  std::string url = "";
  std::string icon_base64 = "";
};

CustomizeNewTabParam_Add::CustomizeNewTabParam_Add() {
  return;
}

void CustomizeNewTabParam_Add::parserFromListValue(const base::ListValue* args) {
  if (!args) {
    return;
  }

  std::string str_json;
  if (args->GetString(0, &str_json)) {
    auto result = base::JSONReader::Read(str_json);
    if (result.has_value()) {
      if (result.value().is_dict()) {
        for (auto _item: result.value().DictItems()) {
          if (_item.first == "sessionID") {
            if (_item.second.is_string()) {
              sessionID = _item.second.GetString();
            }
          } else if (_item.first == "title") {
            if (_item.second.is_string()) {
              title = _item.second.GetString();
            }
          } else if (_item.first == "url") {
            if (_item.second.is_string()) {
              url = _item.second.GetString();
            }
          } else if (_item.first == "icon") {
            if (_item.second.is_string()) {
              icon_base64 = _item.second.GetString();
            }
          } else if (_item.first == "index") {
            if (_item.second.is_int()) {
              index = _item.second.GetInt();
            }
          } 
        }
      }
    }
  }
}

bool CustomizeNewTabParam_Add::is_valid_param() {
  return  (!title.empty()) && (!url.empty()) && (!icon_base64.empty()) && (!sessionID.empty());
}


class CustomizeNewTabParam_Remove: public CustomizeNewTabParam {
public:
  CustomizeNewTabParam_Remove();
  void parserFromListValue(const base::ListValue* args);
  bool is_valid_param();

public:
  std::string itemID;
};


CustomizeNewTabParam_Remove::CustomizeNewTabParam_Remove() {
  itemID = "";
}

void CustomizeNewTabParam_Remove::parserFromListValue(const base::ListValue* args) {
  if (!args) {
    return;
  }
  std::string str_json;
  if (args->GetString(0, &str_json)) {
    auto result = base::JSONReader::Read(str_json);
    if (result.has_value()) {
      if (result.value().is_dict()) {
        for (auto _item: result.value().DictItems()) {
          if (_item.first == "sessionID") {
            if (_item.second.is_string()) {
              sessionID = _item.second.GetString();
            }
            break;
          } else if (_item.first == "itemID") {
            if (_item.second.is_string()) {
              itemID = _item.second.GetString();
            }
          }
        }
      }
    }
  }
}

bool CustomizeNewTabParam_Remove::is_valid_param() {
  return (!sessionID.empty()) && (!itemID.empty());
}

class CustomizeNewTabParam_Update: public CustomizeNewTabParam {
public:
  CustomizeNewTabParam_Update();

public:
  void parserFromListValue(const base::ListValue* args);
  bool is_valid_param();

public:
  int index = -1;
  std::string itemID;
  std::string title = "";
  std::string url = "";
  std::string icon_base64 = "";
};

CustomizeNewTabParam_Update::CustomizeNewTabParam_Update() {
  return;
}

void CustomizeNewTabParam_Update::parserFromListValue(const base::ListValue* args) {
  if (!args) {
    return;
  }

  std::string str_json;
  if (args->GetString(0, &str_json)) {
    auto result = base::JSONReader::Read(str_json);
    if (result.has_value()) {
      if (result.value().is_dict()) {
        for (auto _item: result.value().DictItems()) {
          if (_item.first == "sessionID") {
            if (_item.second.is_string()) {
              sessionID = _item.second.GetString();
            }
          } else if (_item.first == "title") {
            if (_item.second.is_string()) {
              title = _item.second.GetString();
            }
          } else if (_item.first == "url") {
            if (_item.second.is_string()) {
              url = _item.second.GetString();
            }
          } else if (_item.first == "icon") {
            if (_item.second.is_string()) {
              icon_base64 = _item.second.GetString();
            }
          } else if (_item.first == "index") {
            if (_item.second.is_int()) {
              index = _item.second.GetInt();
            }
          } else if (_item.first == "itemID") {
            if (_item.second.is_string()) {
              itemID = _item.second.GetString();
            }
          }
        }
      }
    }
  }
}

bool CustomizeNewTabParam_Update::is_valid_param() {
  return (!itemID.empty()) && ( (index > -1) || (!title.empty()) || (!url.empty()) || (!icon_base64.empty()));
}

void CustomizeNewTabHandler::handleGetCustomizeUrlItems(const base::ListValue* args) {
  CustomizeNewTabParam _param;
  _param.parserFromListValue(args);

  if (!_param.is_valid_param()) {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", false);
    ret_val.SetString("err", "参数错误");

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.getCustomizeUrlItems_callback", v);
    return;
  }

  uos::customize_tab::CustomizeNewTabsCore * tmp_core = 
    (uos::customize_tab::CustomizeNewTabsThreadManager::Get())->getCore();
  
  std::string json_str = tmp_core->jsonStrForCustomizeUrls();
  if (!json_str.empty()) {
      base::DictionaryValue ret_val;
      ret_val.SetBoolean("sucess", true);
      ret_val.SetString("result", json_str);
      ret_val.SetString("sessionID", _param.sessionID);

      std::string payload;
      Value2String(ret_val, payload);
      base::Value v(payload);

      web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.getCustomizeUrlItems_callback", v);

  } else {
      base::DictionaryValue ret_val;
      ret_val.SetBoolean("sucess", true);
      ret_val.SetString("result", "[]");
      ret_val.SetString("sessionID", _param.sessionID);

      std::string payload;
      Value2String(ret_val, payload);
      base::Value v(payload);
      web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.getCustomizeUrlItems_callback", v);
    }
}


void CustomizeNewTabHandler::handleRestoreCustomizeConfigure(const base::ListValue* args) {
  CustomizeNewTabParam _param;
  _param.parserFromListValue(args);

  if (!_param.is_valid_param()) {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", false);
    ret_val.SetString("err", "参数错误");

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.restoreCustomizeConfigure_callback", v);
    return;
  }

   uos::customize_tab::CustomizeNewTabsCore * tmp_core = 
    (uos::customize_tab::CustomizeNewTabsThreadManager::Get())->getCore();

  bool ret = tmp_core->restoreCustomizeConfigure();
  if (ret) {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", true);
    ret_val.SetString("sessionID", _param.sessionID);

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.restoreCustomizeConfigure_callback", v);

    //Nofity Other windows and tabs
    notifyCustomizeUrlItemsChange();


  } else {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", false);
    ret_val.SetString("sessionID", _param.sessionID);
    ret_val.SetString("err", "恢复配置文件失败");

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.restoreCustomizeConfigure_callback", v);

  }
}


void CustomizeNewTabHandler::handleAddCustomizeUrlItems(const base::ListValue* args) {
  CustomizeNewTabParam_Add _param;
  _param.parserFromListValue(args);
  if (!_param.is_valid_param()) {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", false);
    ret_val.SetString("err", "参数错误");

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.addCustomizeUriItem_callback", v);
    return;
  }

  uos::customize_tab::CustomizeUrlItem _item;
  _item.index = _param.index;
  _item.title = _param.title;
  _item.url = _param.url;
  _item.icon_base64 = _param.icon_base64;

  uos::customize_tab::CustomizeNewTabsCore * tmp_core = 
    (uos::customize_tab::CustomizeNewTabsThreadManager::Get())->getCore();

  if (tmp_core->addCustomizeUrlItem(_item)) {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", true);
    ret_val.SetString("sessionID", _param.sessionID);
    ret_val.SetString("itemID", _item.itemID);
    
    if (_param.index == -1) {
       ret_val.SetInteger("index", _item.index);
    }

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.addCustomizeUriItem_callback", v);

    //notify other window and tabs
    notifyCustomizeUrlItemsChange();

  } else {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", false);
    ret_val.SetString("sessionID", _param.sessionID);

    if (_item.code == uos::customize_tab::ErrCode_Item_Exist) {
      ret_val.SetString("err", "exist");

    } else if (_item.code == uos::customize_tab::ErrCode_Item_Exceed) {
      ret_val.SetString("err", "out of range");

    } else {
      ret_val.SetString("err", "添加快捷项失败");
    }
   
    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.addCustomizeUriItem_callback", v);

  }
}


void CustomizeNewTabHandler::handleRemoveCustomizeUrlItems(const base::ListValue* args) {
  CustomizeNewTabParam_Remove _param;
  _param.parserFromListValue(args);
  if (!_param.is_valid_param()) {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", false);
    ret_val.SetString("err", "参数错误");

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.removeCustomizeUrlItem_callback", v);
    return;
  }

  uos::customize_tab::CustomizeNewTabsCore * tmp_core = 
    (uos::customize_tab::CustomizeNewTabsThreadManager::Get())->getCore();

  if (tmp_core->removeCustomizeUrlItem(_param.itemID)) {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", true);
    ret_val.SetString("sessionID", _param.sessionID);
    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.removeCustomizeUrlItem_callback", v);
    notifyCustomizeUrlItemsChange();

  } else {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", false);
    ret_val.SetString("sessionID", _param.sessionID);
    ret_val.SetString("err", "删除快捷项失败");

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.removeCustomizeUrlItem_callback", v);
  }
}


void CustomizeNewTabHandler::handleUpdateCustomizeUrlItems(const base::ListValue* args) {
  CustomizeNewTabParam_Update _param;
   _param.parserFromListValue(args);
  if (!_param.is_valid_param()) {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", false);
    ret_val.SetString("err", "参数错误");

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.updateCustomizeUrlItem_callback", v);
    return;
  }

  uos::customize_tab::CustomizeNewTabsCore * tmp_core = 
    (uos::customize_tab::CustomizeNewTabsThreadManager::Get())->getCore();

  uos::customize_tab::CustomizeUrlItem _item;
  _item.index = _param.index;
  _item.title = _param.title;
  _item.url = _param.url;
  _item.icon_base64 = _param.icon_base64;
  _item.itemID = _param.itemID;

  if (tmp_core->updateCustomizeUrlItem(_item)) {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", true);
    ret_val.SetString("sessionID", _param.sessionID);
    
    if (!_item.icon_base64.empty()) {
      ret_val.SetString("icon", _item.icon_base64);
    }

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.updateCustomizeUrlItem_callback", v);
    notifyCustomizeUrlItemsChange();

  } else {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", false);
    ret_val.SetString("sessionID", _param.sessionID);

    if (_item.code == uos::customize_tab::ErrCode_Item_Exist) {
       ret_val.SetString("err", "exist");
    } else {
      ret_val.SetString("err", "更新快捷项失败");
    }

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.updateCustomizeUrlItem_callback", v);
  }
}

class CustomizeNewTabParam_ValidUrl: public CustomizeNewTabParam {
public:
  CustomizeNewTabParam_ValidUrl();
  void parserFromListValue(const base::ListValue* args);
  bool is_valid_param();

public:
  std::string url = "";

};

CustomizeNewTabParam_ValidUrl::CustomizeNewTabParam_ValidUrl() {
  return;
}

void CustomizeNewTabParam_ValidUrl::parserFromListValue(const base::ListValue* args) {
   if (!args) {
    return;
  }

  std::string str_json;
  if (args->GetString(0, &str_json)) {
    auto result = base::JSONReader::Read(str_json);
    if (result.has_value()) {
      if (result.value().is_dict()) {
        for (auto _item: result.value().DictItems()) {
          if (_item.first == "sessionID") {
            if (_item.second.is_string()) {
              sessionID = _item.second.GetString();
            }
          } else if (_item.first == "url") {
            if (_item.second.is_string()) {
              url = _item.second.GetString();
            }
          } 
        }
      }
    }
  }
}

bool CustomizeNewTabParam_ValidUrl::is_valid_param() {
  return (!sessionID.empty()) && (!url.empty());
}


void CustomizeNewTabHandler::handleValidUrl(const base::ListValue * args) {
  CustomizeNewTabParam_ValidUrl _param;
   _param.parserFromListValue(args);

  if (!_param.is_valid_param()) {
    base::DictionaryValue ret_val;
    ret_val.SetBoolean("sucess", false);
    ret_val.SetString("err", "参数错误");
    if (!_param.sessionID.empty()) {
      ret_val.SetString("sessionID", _param.sessionID);
    }

    std::string payload;
    Value2String(ret_val, payload);
    base::Value v(payload);

    web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.handleValidUrl_callback", v);
    return;
  }

  bool valid = settings_utils::FixupAndValidateStartupPage(_param.url, nullptr);

  {
      base::DictionaryValue ret_val;
      ret_val.SetBoolean("sucess", true);
      ret_val.SetString("sessionID", _param.sessionID);
      ret_val.SetBoolean("valid", valid);

      std::string payload;
      Value2String(ret_val, payload);
      base::Value v(payload);

      web_ui()->CallJavascriptFunctionUnsafe("uos_newtab.validUrl_callback", v);

  }

}


void CustomizeNewTabHandler::notifyCustomizeUrlItemsChange() {
  int browserCount = BrowserList::GetInstance()->size();

  uos::customize_tab::CustomizeNewTabsCore * tmp_core = 
    (uos::customize_tab::CustomizeNewTabsThreadManager::Get())->getCore();
  
  std::string json_str = tmp_core->jsonStrForCustomizeUrls();
  base::DictionaryValue ret_val;

  if (!json_str.empty()) {
    ret_val.SetBoolean("sucess", true);
    ret_val.SetString("result", json_str);
    ret_val.SetString("sessionID", "**");
  } else {
    ret_val.SetBoolean("sucess", true);
    ret_val.SetString("result", "[]");
    ret_val.SetString("sessionID", "**");
  }

  std::string payload;
  Value2String(ret_val, payload);
  base::Value v(payload);

  for (int bi = 0; bi < browserCount; bi++) {
    Browser* bw = BrowserList::GetInstance()->get(bi);
    if (!bw) {
      continue;
    }
    auto p = bw->profile();

    if (p && (!p->IsIncognitoProfile())) {
      TabStripModel* tsm = bw->tab_strip_model();
      if (!tsm) {
        continue;
      }
      int tsmCount = tsm->count();
      for (int ti = 0; ti < tsmCount; ti++) {
        content::WebContents* wc = tsm->GetWebContentsAt(ti);
        if (!wc || !(wc->GetWebUI())) {
          continue;
        }
        if (wc && (wc->GetWebUI() != web_ui())) {
          GURL url = wc->GetURL();
          if (url.host_piece() == chrome::kChromeUINewTabHost) {
            wc->GetWebUI()->CallJavascriptFunctionUnsafe("uos_newtab.onCustomizeUrlItemsChange", v);
          } 
        }
      }
    }
  }
}


