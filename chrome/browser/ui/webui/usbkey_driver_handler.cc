// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef OPENSSL_NO_GMTLS
#include "chrome/browser/ui/webui/usbkey_driver_handler.h"

#include <algorithm>
#include <string>
#include <utility>

#include "base/bind.h"
#include "base/json/json_file_value_serializer.h"
#include "base/json/json_reader.h"
#include "base/json/json_string_value_serializer.h"
#include "base/json/json_writer.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/user_metrics.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/values.h"
#include "base/files/file_util.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_list.h"
#include "chrome/common/pref_names.h"
#include "chrome/common/url_constants.h"
#include "chrome/grit/generated_resources.h"
#include "components/prefs/pref_service.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_ui.h"
#include "content/public/browser/web_ui_message_handler.h"

#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/chrome_select_file_policy.h"
#include "ui/base/l10n/l10n_util.h"
#include "third_party/boringssl/src/crypto/skf/skf_manager.h"

namespace {
// The following strings need to match with the IDs of the text input elements
// at settings/search_engines_page/search_engine_dialog.html.
const char kUsbKeyDriverName[] = "driver";
const char kUsbKeyDriverPath[] = "queryUrl";

// Dummy number used for indicating that a new search engine is added.
//const int kNewSearchEngineIndex = -1;

}  // namespace

namespace usbkeydriver_manager {

USBKeyDriverHandler::USBKeyDriverHandler(Profile* profile) 
  : profile_(profile) {
}

USBKeyDriverHandler::~USBKeyDriverHandler() {
  if (select_folder_dialog_.get())
    select_folder_dialog_->ListenerDestroyed();
}

void USBKeyDriverHandler::RegisterMessages() {
  LOG(ERROR) << "USBKeyDriverHandler::RegisterMessages()1117";
  web_ui()->RegisterMessageCallback(
      "getUSBKeyDriversList",
      base::BindRepeating(&USBKeyDriverHandler::HandleGetUSBKeyDriversList,
                          base::Unretained(this)));
  web_ui()->RegisterMessageCallback(
      "removeUSBKeyDriver",
      base::BindRepeating(&USBKeyDriverHandler::HandleRemoveUSBKeyDriver,
                          base::Unretained(this)));
  web_ui()->RegisterMessageCallback(
      "USBKeyDriverEditStarted",
      base::BindRepeating(&USBKeyDriverHandler::HandleUSBKeyDriverEditStarted,
                          base::Unretained(this)));
  web_ui()->RegisterMessageCallback(
      "validateUSBKeyDriverInput",
      base::BindRepeating(
          &USBKeyDriverHandler::HandleValidateUSBKeyDriverInput,
          base::Unretained(this)));
  web_ui()->RegisterMessageCallback(
      "USBKeyDriverEditCancelled",
      base::BindRepeating(&USBKeyDriverHandler::HandleUSBKeyDriverEditCancelled,
                          base::Unretained(this)));
  web_ui()->RegisterMessageCallback(
      "USBKeyDriverEditCompleted",
      base::BindRepeating(
          &USBKeyDriverHandler::HandleUSBKeyDriverEditCompleted,
          base::Unretained(this)));

   web_ui()->RegisterMessageCallback(
      "USBKeyDriverSelectLocation",
      base::BindRepeating(
          &USBKeyDriverHandler::HandleUSBKeyDriverSelectLocation,
          base::Unretained(this)));
}

void USBKeyDriverHandler::OnJavascriptAllowed() {
}

void USBKeyDriverHandler::OnJavascriptDisallowed() {
}

base::DictionaryValue*
USBKeyDriverHandler::GetUSBKeyDriversList() {
  PrefService* pref_service = profile_->GetPrefs();
  pref_service->SetFilePath(prefs::kUsbKeyDirectory, base::FilePath());

  auto dict = const_cast<base::DictionaryValue*>(profile_->GetPrefs()->GetDictionary(prefs::kUsbKeyDriverManager));
  if (!dict->empty()) {
    m_deviceid = 0;
    base::ListValue *listvalue;
    dict->GetList("driver_info", &listvalue);
    for(size_t i = 0; i<listvalue->GetSize(); i++)
    {
      base::DictionaryValue *value;
      listvalue->GetDictionary(i, &value);
      value->SetInteger("id", m_deviceid++);
      std::string path;
      value->GetString("path",&path);
      if(access(path.c_str(),F_OK) == -1)
      {
        value->SetBoolean("valid",false);
      }
      else
      {
        value->SetBoolean("valid",true);
      }      
    }
  }
  return dict;
}

void USBKeyDriverHandler::HandleGetUSBKeyDriversList(
    const base::ListValue* args) {
  CHECK_EQ(1U, args->GetSize());
  const base::Value* callback_id;
  CHECK(args->Get(0, &callback_id));
  std::string name;
  std::string path;
  args->GetString(0, &name);
  args->GetString(1, &path);
  AllowJavascript();
  ResolveJavascriptCallback(*callback_id, *GetUSBKeyDriversList());
}

void USBKeyDriverHandler::HandleRemoveUSBKeyDriver(
    const base::ListValue* args) {
  int index;
  if (!ExtractIntegerValue(args, &index)) {
    NOTREACHED();
    return;
  }

  auto dict = const_cast<base::DictionaryValue*>(profile_->GetPrefs()->GetDictionary(prefs::kUsbKeyDriverManager));
  base::ListValue *listvalue;
  dict->GetList("driver_info", &listvalue);

  listvalue->Remove(index, nullptr);
}

void USBKeyDriverHandler::HandleUSBKeyDriverEditStarted(
    const base::ListValue* args) {
  int index;
  if (!ExtractIntegerValue(args, &index)) {
    NOTREACHED();
    return;
  }
}

void USBKeyDriverHandler::HandleValidateUSBKeyDriverInput(
    const base::ListValue* args) {

  CHECK_EQ(3U, args->GetSize());

  const base::Value* callback_id;
  std::string field_name;
  std::string field_value;
  CHECK(args->Get(0, &callback_id));
  CHECK(args->GetString(1, &field_name));
  CHECK(args->GetString(2, &field_value));
  ResolveJavascriptCallback(
      *callback_id, base::Value(CheckFieldValidity(field_name, field_value)));
}

bool USBKeyDriverHandler::CheckFieldValidity(const std::string& field_name,
                                              const std::string& field_value) {
  bool is_valid = false;
  if (field_name.compare(kUsbKeyDriverName) == 0)
    is_valid = !base::CollapseWhitespace(base::UTF8ToUTF16(field_value), true).empty();
  else if (field_name.compare(kUsbKeyDriverPath) == 0)
  {
    LOG(ERROR) << "call IsDriverPathValid before";
    is_valid = IsDriverPathValid(field_value);
    LOG(ERROR) << "call IsDriverPathValid after";
  }
  else
    NOTREACHED();
  LOG(ERROR) << "CheckFieldValidity is_valid = " << is_valid;
  return is_valid;
}

bool USBKeyDriverHandler::IsDriverPathValid(const std::string& driver_path) const {
  if (base::CollapseWhitespace(base::UTF8ToUTF16(driver_path), true).empty()) {
    LOG(ERROR) << "driver_path empty";
    return false;
  }

  skf_module_enumerator* mods = skf_module_enumerator::get_enumerator();
  if(mods->check_lib_valid(driver_path)) {
    LOG(ERROR) << "mods.check_lib_valid(driver_path) = true";
    return true;
  } else {
    LOG(ERROR) << "mods.check_lib_valid(driver_path) = false";
    return false;
  }
}

void USBKeyDriverHandler::HandleUSBKeyDriverEditCancelled(
    const base::ListValue* args) {
  PrefService* pref_service = profile_->GetPrefs();
  pref_service->SetFilePath(prefs::kUsbKeyDirectory, base::FilePath());
}

void USBKeyDriverHandler::HandleUSBKeyDriverEditCompleted(
    const base::ListValue* args) {
  int id;
  std::string name;
  std::string path;

  args->GetInteger(0, &id);
  args->GetString(1, &name);
  args->GetString(2, &path);

  std::string driver_contents;
  base::ReadFileToString(base::FilePath(path), &driver_contents);
  auto md5string = base::MD5String(driver_contents);

  auto driver_mgr_dict = const_cast<base::DictionaryValue*>(
    profile_->GetPrefs()->GetDictionary(prefs::kUsbKeyDriverManager));

  if (id == -1) {
    if (driver_mgr_dict->empty())
    {
      auto dict = std::make_unique<base::DictionaryValue>();
      dict->SetInteger("id", m_deviceid++);
      dict->SetString("name", name);
      dict->SetString("path", path);
      dict->SetString("md5value", md5string);
      auto listvalue = std::make_unique<base::ListValue>();
      listvalue->Append(std::move(dict));
      auto list = listvalue->CreateDeepCopy();
      auto driver_info = std::make_unique<base::DictionaryValue>();
      driver_info->Set("driver_info", std::move(list));
      profile_->GetPrefs()->Set(prefs::kUsbKeyDriverManager, *driver_info);
    } else {
      base::ListValue *listvalue;
      driver_mgr_dict->GetList("driver_info", &listvalue);
      for(size_t i = 0; i < listvalue->GetSize(); i++) {
        base::DictionaryValue *value;
        listvalue->GetDictionary(i, &value);
        std::string md5_out;
        if (value->GetString("md5value", &md5_out) && md5_out == md5string)
          listvalue->Remove(i, nullptr);
      }
      auto dict = std::make_unique<base::DictionaryValue>();
      dict->SetInteger("id", m_deviceid++);
      dict->SetString("name", name);
      dict->SetString("path", path);
      dict->SetString("md5value", md5string);
      listvalue->Append(std::move(dict));
    }
  } else {
    std::string md5_out;
    base::ListValue *listvalue;
    driver_mgr_dict->GetList("driver_info", &listvalue);
    for(size_t j = 0; j < listvalue->GetSize(); j++) {
      base::DictionaryValue *value;
      listvalue->GetDictionary(j, &value);
      if (value->GetString("md5value", &md5_out) && md5_out == md5string) {
            listvalue->Remove(j, nullptr);
          }
    }

    for(size_t i = 0; i < listvalue->GetSize(); i++)
    {
      base::DictionaryValue *value;
      listvalue->GetDictionary(i, &value);
      int id_out;

      if (value->GetInteger("id", &id_out) && id_out == id) {
        value->SetString("name", name);
        value->SetString("path", path);
        value->SetString("md5value", md5string);
        return;
      }
    }
    auto dict = std::make_unique<base::DictionaryValue>();
    dict->SetInteger("id", m_deviceid++);
    dict->SetString("name", name);
    dict->SetString("path", path);
    dict->SetString("md5value", md5string);
    listvalue->Append(std::move(dict));
  }

  PrefService* pref_service = profile_->GetPrefs();
  pref_service->SetFilePath(prefs::kUsbKeyDirectory, base::FilePath());
}

void USBKeyDriverHandler::HandleUSBKeyDriverSelectLocation(const base::ListValue* args) {
  PrefService* pref_service = profile_->GetPrefs();
  select_folder_dialog_ = ui::SelectFileDialog::Create(
      this,
      std::make_unique<ChromeSelectFilePolicy>(web_ui()->GetWebContents()));
  ui::SelectFileDialog::FileTypeInfo info;
  info.allowed_paths = ui::SelectFileDialog::FileTypeInfo::NATIVE_PATH;
  select_folder_dialog_->SelectFile(
      ui::SelectFileDialog::SELECT_OPEN_FILE,
      l10n_util::GetStringUTF16(IDS_SETTINGS_DOWNLOAD_LOCATION),
      pref_service->GetFilePath(prefs::kUsbKeyDirectory), &info, 0,
      base::FilePath::StringType(),
      web_ui()->GetWebContents()->GetTopLevelNativeWindow(), NULL); 

}

void USBKeyDriverHandler::FileSelected(const base::FilePath& path,
                                    int index,
                                    void* params) {
  PrefService* pref_service = profile_->GetPrefs();
  pref_service->SetFilePath(prefs::kUsbKeyDirectory, path);
  base::FilePath p = pref_service->GetFilePath(prefs::kUsbKeyDirectory);
}

}  // namespace settings
#endif //#OPENSSL_NO_GMTLS