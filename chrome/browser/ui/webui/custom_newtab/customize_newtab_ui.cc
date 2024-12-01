#include "chrome/browser/ui/webui/custom_newtab/customize_newtab_ui.h"

#include "base/values.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/webui/custom_newtab/customize_newtab_handler.h"
#include "chrome/common/url_constants.h"
#include "chrome/grit/browser_resources.h"
#include "chrome/grit/generated_resources.h"
#include "components/strings/grit/components_strings.h"
#include "content/public/browser/web_ui.h"
#include "content/public/browser/web_ui_data_source.h"

CustomizeNewTabUI::CustomizeNewTabUI(content::WebUI* web_ui1)
    : content::WebUIController(web_ui1) {
    LOG(INFO) << "CustomizeNewTabUI::CustomizeNewTabUI1";
    Profile *profile = Profile::FromWebUI(web_ui1);
    web_ui()->AddMessageHandler(
        std::make_unique<CustomizeNewTabHandler>(profile));

    // Set up the chrome://hello-world source.
    content::WebUIDataSource *html_source =
        content::WebUIDataSource::Create(chrome::kChromeUINewTabHost);

    // Localized strings.
    // html_source->AddLocalizedString("newtabTitle", IDS_NEWTAB_TITLE);
    html_source->AddLocalizedString("newtabTitle", IDS_NEWTAB_TITLE);
    html_source->AddLocalizedString("testtext", IDS_ABOUT_BROWSER);
    html_source->AddLocalizedString("webpage", IDS_NEWTAB_WEBPAGE);
    html_source->AddLocalizedString("images", IDS_NEWTAB_IMAGES);
    html_source->AddLocalizedString("news", IDS_NEWTAB_NEWS);
    html_source->AddLocalizedString("videos", IDS_NEWTAB_VIDEOS);
    html_source->AddLocalizedString("maps", IDS_NEWTAB_MAPS);
    html_source->AddLocalizedString("search", IDS_NEWTAB_SEARCH);
    html_source->AddLocalizedString("search_engine_baidu", IDS_NEWTAB_SEARCH_ENGINE_BAIDU);
    html_source->AddLocalizedString("search_engine_sogou", IDS_NEWTAB_SEARCH_ENGINE_SOGOU);

    html_source->AddLocalizedString("undo",IDS_NEW_TAB_UNDO_THUMBNAIL_REMOVE);
    html_source->AddLocalizedString("addLinkTitle", IDS_NTP_CUSTOM_LINKS_ADD_SHORTCUT_TITLE);
    html_source->AddLocalizedString("editLinkTitle", IDS_NTP_CUSTOM_LINKS_EDIT_SHORTCUT);
    html_source->AddLocalizedString("invalidUrl", IDS_NTP_CUSTOM_LINKS_INVALID_URL);
    html_source->AddLocalizedString("linkAddedMsg", IDS_NTP_CONFIRM_MSG_SHORTCUT_ADDED);
    html_source->AddLocalizedString("linkCancel", IDS_NTP_CUSTOM_LINKS_CANCEL);
    html_source->AddLocalizedString("linkCantCreate", IDS_NTP_CUSTOM_LINKS_CANT_CREATE);
    html_source->AddLocalizedString("linkCantEdit", IDS_NTP_CUSTOM_LINKS_CANT_EDIT);
    html_source->AddLocalizedString("linkDone", IDS_NTP_CUSTOM_LINKS_DONE);
    html_source->AddLocalizedString("linkEditedMsg", IDS_NTP_CONFIRM_MSG_SHORTCUT_EDITED);
    html_source->AddLocalizedString("linkRemove", IDS_REMOVE);
    html_source->AddLocalizedString("linkRemovedMsg", IDS_NTP_CONFIRM_MSG_SHORTCUT_REMOVED);
    html_source->AddLocalizedString("nameField", IDS_NTP_CUSTOM_LINKS_NAME);
    html_source->AddLocalizedString("restoreDefaultLinks", IDS_NTP_CONFIRM_MSG_RESTORE_DEFAULTS);
    html_source->AddLocalizedString("restoreThumbnailsShort", IDS_NEW_TAB_RESTORE_THUMBNAILS_SHORT_LINK);
    html_source->AddLocalizedString("urlField", IDS_NTP_CUSTOM_LINKS_URL);
    html_source->AddLocalizedString("nameError", IDS_FILL_IN_A_NAME);
    //   {"undo", },

    //   // Custom Links
    //   {"addLinkTitle", IDS_NTP_CUSTOM_LINKS_ADD_SHORTCUT_TITLE},
    //   {"editLinkTitle", IDS_NTP_CUSTOM_LINKS_EDIT_SHORTCUT},
    //   {"invalidUrl", IDS_NTP_CUSTOM_LINKS_INVALID_URL},
    //   {"linkAddedMsg", },
    //   {"linkCancel", IDS_NTP_CUSTOM_LINKS_CANCEL},
    //   {"linkCantCreate", },
    //   {"linkCantEdit", },
    //   {"linkDone", },
    //   {"linkEditedMsg", },
    //   {"linkRemove", },
    //   {"linkRemovedMsg", IDS_NTP_CONFIRM_MSG_SHORTCUT_REMOVED},
    //   {"nameField", IDS_NTP_CUSTOM_LINKS_NAME},
    //   {"restoreDefaultLinks", IDS_NTP_CONFIRM_MSG_RESTORE_DEFAULTS},
    //   {"restoreThumbnailsShort", IDS_NEW_TAB_RESTORE_THUMBNAILS_SHORT_LINK},
    //   {"urlField", IDS_NTP_CUSTOM_LINKS_URL},

    // html_source->AddLocalizedString("welcomeMessage",
    // IDS_HELLO_WORLD_WELCOME_TEXT);

    // As a demonstration of passing a variable for JS to use we pass in the name
    // "Bob".
    html_source->AddString("userName", "Bob");
    // html_source->SetJsonPath("strings.js");
    html_source->UseStringsJs();

    // Add required resources.
    html_source->AddResourcePath("normal.css", IDR_NORMAL_CSS);
    html_source->AddResourcePath("jquery.js", IDR_JQUERY_JS);
    html_source->AddResourcePath("right_click.js", IDR_RIGHTCLICK_JS);
    html_source->AddResourcePath("customize_newtab.css",
                                 IDR_CUSTOMIZE_NEWTAB_CSS);
    html_source->AddResourcePath("customize_newtab.js", IDR_CUSTOMIZE_NEWTAB_JS);
    html_source->SetDefaultResource(IDR_CUSTOMIZE_NEWTAB_HTML);

    content::WebUIDataSource::Add(profile, html_source);

    LOG(INFO) << "CustomizeNewTabUI::CustomizeNewTabUI2";
}

CustomizeNewTabUI::~CustomizeNewTabUI() {}