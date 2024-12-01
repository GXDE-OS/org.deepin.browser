#include <iostream>

#include "base/json/json_file_value_serializer.h"
#include "base/json/json_reader.h"
#include "base/json/json_string_value_serializer.h"
#include "base/json/json_writer.h"

#include "base/values.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/path_service.h"

#include "base/hash/md5.h"
#include "base/strings/string_util.h"

#include "customize_newtabs_core.h"
#include "chrome/common/chrome_paths.h"
#include "base/linux_util.h"
#include "base/guid.h"
#include "base/hash/md5.h"
#include "url/gurl.h"



namespace uos {
namespace customize_tab {
bool CustomizeUrlItem::is_validate() {
    if (itemID.empty() || title.empty() || url.empty() || icon_base64.empty()) {
        return false;
    }
    if (index < 0) {
        return false;
    }
    return true;
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

bool urlItems2String(std::vector<CustomizeUrlItem> & in_items, std::string & out) {
    base::ListValue root_v;
    for (auto _item: in_items) {
        base::DictionaryValue * dv_pt = new base::DictionaryValue();
        dv_pt->SetInteger("index", _item.index);
        dv_pt->SetString("title", _item.title);
        dv_pt->SetString("url", _item.url);
        dv_pt->SetString("icon", _item.icon_base64);
        dv_pt->SetString("itemID", _item.itemID);
        root_v.Append(std::unique_ptr<base::Value>(dv_pt));
    }
    return Value2String(root_v, out);
}

std::string getDefaultNaviUrlsForPlatform(base::Value & in_navi) {
    if (in_navi.is_none() || !in_navi.is_dict()) {
        return std::string();
    }
    std::string uos_version = base::GetUosEdition();
    std::string _result = "";
    std::string _default = "";

    for (auto _item: in_navi.DictItems()) {
        if (base::CompareCaseInsensitiveASCII(uos_version, _item.first) == 0) {
            Value2String(_item.second, _result);
        } else if (base::CompareCaseInsensitiveASCII("Default", _item.first) == 0) {
            Value2String(_item.second, _default);
        }
    }
    if (!_result.empty()) {
        return _result;
    }
    if (!_default.empty()) {
        return _default;
    }
    return std::string();
}

CustomizeNewTabsCore::CustomizeNewTabsCore() {
    //std::cout << "\r\n\r\nxiangye==> CustomizeNewTabsCore Construct...." << std::endl << std::endl;
    loadDefaultConfigure();
    loadCustomizeConfigure();
}


int CustomizeNewTabsCore::newIndexForCurrentItems() {
    int idx = -1;
    for (auto item: current_items_) {
        if (item.index > idx) {
            idx = item.index;
        }
    }
    idx ++;
    return idx;
}


std::string CustomizeNewTabsCore::iconForUrl(std::string in_url) {
    GURL _in_host_url(in_url);
    for (auto item: default_items_) {
        GURL _tmp(item.url);
        if (_in_host_url.has_host() && (_in_host_url.host() == _tmp.host())) {
            return item.icon_base64;

        }
    }
    return std::string();
}


bool CustomizeNewTabsCore::addCustomizeUrlItem(CustomizeUrlItem & in_item) {
    std::string _url = std::string(in_item.url);
    if (base::TrimString(_url, " ", &_url)) {
        in_item.url = std::string(_url);
    }

    for (auto _item: current_items_) {
        if (base::CompareCaseInsensitiveASCII(_item.url, _url) == 0) {
            in_item.code = ErrCode_Item_Exist; //the item is exist.
            return false;
        }
    }

    if (current_items_.size() > 11) {// currently, the maxium counts is 12.
        in_item.code = ErrCode_Item_Exceed;
        return false;
    }
    
    if (in_item.index < 0) {
        in_item.index = newIndexForCurrentItems();
    }
    in_item.itemID = base::GenerateGUID();
    auto _icon = iconForUrl(in_item.url);
    if (!_icon.empty()) {
        in_item.icon_base64 = _icon;
    }
   
    current_items_.push_back(in_item);
    return serializeCustomizeUrls();
}

bool CustomizeNewTabsCore::removeCustomizeUrlItem(std::string in_itemID) {
    for (auto pos = current_items_.begin(); pos != current_items_.end(); pos ++) {
        if (pos->itemID == in_itemID) {
            current_items_.erase(pos);
            return serializeCustomizeUrls();
        }
    }
    return false;
}

bool CustomizeNewTabsCore::updateCustomizeUrlItem(CustomizeUrlItem & in_item) {
    std::string _url = std::string(in_item.url);
    if (base::TrimString(_url, " ", &_url)) {
        in_item.url = std::string(_url);
    }

    for (auto _item: current_items_) {
        if ((base::CompareCaseInsensitiveASCII(_item.url, _url) == 0) && 
            (base::CompareCaseInsensitiveASCII(_item.itemID, in_item.itemID) != 0)  ) {
            in_item.code = ErrCode_Item_Exist; //the item is exist.
            return false;
        }
    }

    for (auto pos = current_items_.begin(); pos != current_items_.end(); pos ++) {
        if (base::CompareCaseInsensitiveASCII(pos->itemID, in_item.itemID) == 0) {
            bool change = false;

            if (in_item.index > 0) {
                pos->index = in_item.index;
                change = true;
            }

            if (!in_item.title.empty()) {
                pos->title = in_item.title;
                change = true;
            }

            if (!in_item.url.empty()) {
                pos->url = in_item.url;
                auto _icon = iconForUrl(in_item.url);
                if (!_icon.empty()) {
                    pos->icon_base64 = _icon;
                    in_item.icon_base64 =_icon;
                }
               
                change = true;
            }
            if (!in_item.icon_base64.empty()) {
                pos->icon_base64 = in_item.icon_base64;
                in_item.icon_base64 = std::string();
                change = true;
            }
            if (change) {
                return serializeCustomizeUrls();
            }
            return true;
        }
    }

    return false;

}

bool CustomizeNewTabsCore::restoreCustomizeConfigure() {
    if (default_items_.size() == 0) {
        return false;
    }
    current_items_ = default_items_;
    return serializeCustomizeUrls();
}

std::string CustomizeNewTabsCore::jsonStrForCustomizeUrls() {
    if (current_items_.size() > 0) {
        std::string json_str = "";
        bool ret = urlItems2String(current_items_, json_str);
        if (ret) {
            return json_str;
        }
    }
    return "";
}

std::string CustomizeNewTabsCore::defaultTemplateFilePath() {
    if (template_file_path_.empty()) {
        base::FilePath data_dir;
        if (base::PathService::Get(chrome::DIR_UOS_USR_SHARE_BROWSER, &data_dir)) {
            base::FilePath data_file = base::FilePath(data_dir.Append("master_preferences"));
            template_file_path_ = data_file.value();
        }

    }
    //std::cout << "\r\n" << template_file_path_ << std::endl << "\r\n";
    return template_file_path_;
}

std::string CustomizeNewTabsCore::customizeUrlsFilePath() {
    if (path_for_user_.empty()) {
        base::FilePath home_ = base::GetHomeDir();
        auto userID = getuid();
        std::string ret = home_.value() + "/.config/browser/customize_tabls_";
        ret += std::to_string(userID);
        ret += ".conf";
        path_for_user_ = ret;

    }
    return path_for_user_;
}

bool CustomizeNewTabsCore::parseCustomizeUrlsFromJSON(std::string in_json, std::vector<CustomizeUrlItem> & out) {
    if (in_json.empty()) {
        return false;
    }
    auto result = base::JSONReader::Read(in_json);
    if (!result.has_value()) {
        return false;
    }
    if (!result.value().is_list()) {
        return false;
    }

    base::ListValue * lvp = nullptr;

    if (!(result.value().GetAsList(&lvp))) {
        return false;
    }
    int lv_size = lvp->GetSize();
    for (int idx = 0; idx < lv_size; idx ++) {
        base::DictionaryValue * dvp = nullptr;
        bool _ret = lvp->GetDictionary(idx, & dvp);
        if (_ret) {
            CustomizeUrlItem urlItem;
            for (auto _item: dvp->DictItems()) {
                if (base::CompareCaseInsensitiveASCII(_item.first, "index") == 0) {
                    urlItem.index = _item.second.GetInt();
                }
                if (base::CompareCaseInsensitiveASCII(_item.first, "title") == 0) {
                    urlItem.title = _item.second.GetString();
                }

                if (base::CompareCaseInsensitiveASCII(_item.first, "url") == 0) {
                    urlItem.url = _item.second.GetString();
                }

                if (base::CompareCaseInsensitiveASCII(_item.first, "icon") == 0) {
                    urlItem.icon_base64 =_item.second.GetString();
                }
                if (base::CompareCaseInsensitiveASCII(_item.first, "itemID") == 0) {
                    urlItem.itemID = _item.second.GetString();
                }
            }
            if (urlItem.itemID.empty()) {
                urlItem.itemID = base::GenerateGUID();
            }
            if (urlItem.is_validate()) {
                out.push_back(urlItem);
            }
        }
    }
    return true;
}

bool CustomizeNewTabsCore::loadDefaultConfigure() {
    base::FilePath path_(defaultTemplateFilePath());
    std::string json_str;
    if (!base::PathExists(path_)) {
        return false;
    }
    if (!base::ReadFileToString(path_, &json_str)) {
        return false;
    }
    auto result = base::JSONReader::Read(json_str);
    std::string ret = "";
    if (result.has_value()) {
        if (result.value().is_dict()) {
            for (auto _item: result.value().DictItems()) {
                if (_item.first == "navigations") {
                    ret = getDefaultNaviUrlsForPlatform(_item.second);
                    break;
                }
            }
        }
    }
    if (ret.empty()) {
        return false;
    }

    std::vector<CustomizeUrlItem> _items;
    bool _parse_result = parseCustomizeUrlsFromJSON(ret, _items);
    if (_parse_result) {
        default_items_ = _items;
    }
    return true;

}

bool CustomizeNewTabsCore::checkCustomizeConfigure() {
    base::FilePath path_(customizeUrlsFilePath());

    if (!base::PathExists(path_)) { //configure file not exist
        if (!restoreCustomizeConfigure()) {
            return false;
        }
    }
    std::string json_str;
    if (!base::ReadFileToString(path_, &json_str)) {
        return false;
    }

    auto pos = json_str.rfind("\r\nhash:");
    if (pos == std::string::npos) {
        return false;
    }

    std::string rep_str = json_str.substr(0, pos);
    std::string md5_str = json_str.substr(pos + 7);

    if (base::CompareCaseInsensitiveASCII(md5_str, base::MD5String(rep_str)) == 0) {
        return true;
    }
    return false;

}

bool CustomizeNewTabsCore::loadCustomizeConfigure() {
    if (!checkCustomizeConfigure()) {
        restoreCustomizeConfigure();
    }

    base::FilePath path_(customizeUrlsFilePath());
    std::string json_str;
    if (!base::ReadFileToString(path_, &json_str)) {
        return false;
    }

    auto pos = json_str.rfind("\r\nhash:");
    if (pos == std::string::npos) {
        return false;
    }

    std::string rep_str = json_str.substr(0, pos);
    std::vector<CustomizeUrlItem> _items;
    if (parseCustomizeUrlsFromJSON(rep_str, _items)) {
        current_items_ = _items;
        return true;
    }
    return false;
}

bool CustomizeNewTabsCore::serializeCustomizeUrls() {
    std::string rep_str;
    if (!urlItems2String(current_items_, rep_str)) {
        return false;
    }
    std::string _hash = base::MD5String(rep_str);
    std::string _result = rep_str + "\r\nhash:" + _hash;

    base::FilePath _tmp_path(customizeUrlsFilePath());
    if (base::WriteFile(_tmp_path, _result.c_str(), strlen(_result.c_str())) == -1) {
        return false;
    }
    return true;
}

}
}