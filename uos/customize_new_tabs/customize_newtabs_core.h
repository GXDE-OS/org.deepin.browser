
#ifndef _CUSTOM_NEWTABS_MNGR_H_
#define _CUSTOM_NEWTABS_MNGR_H_

#include <string>
#include <vector>

namespace uos{
namespace customize_tab{


enum ErrCode {
    ErrCode_Unknow = -1,
    ErrCode_Item_Exist = 0,   
    ErrCode_Item_Exceed = 1,
    ErrCode_Item_Not_Exist = 2
};

struct CustomizeUrlItem {
    std::string itemID = "";
    int index = -1;

    std::string title = "";
    std::string url = "";
    std::string icon_base64 = "";

    ErrCode code = ErrCode::ErrCode_Unknow;
    bool is_validate();

};

class CustomizeNewTabsCore {
public: 
    CustomizeNewTabsCore();

public:
    bool addCustomizeUrlItem(CustomizeUrlItem & in_item);
    bool removeCustomizeUrlItem(std::string in_itemID);
    bool updateCustomizeUrlItem(CustomizeUrlItem & in_item);
    bool restoreCustomizeConfigure();
    std::string jsonStrForCustomizeUrls();

private:
    std::string defaultTemplateFilePath();
    std::string customizeUrlsFilePath();

private:
    bool loadDefaultConfigure();
    bool loadCustomizeConfigure();
    bool checkCustomizeConfigure();

    bool parseCustomizeUrlsFromJSON(std::string in_json, std::vector<CustomizeUrlItem> & out);
    bool serializeCustomizeUrls();

    int newIndexForCurrentItems();

    std::string iconForUrl(std::string in_url);

private:
    std::vector<CustomizeUrlItem> default_items_;
    std::vector<CustomizeUrlItem> current_items_;


    std::string template_file_path_ = "";
    std::string path_for_user_ = "";
};
}
}



#endif