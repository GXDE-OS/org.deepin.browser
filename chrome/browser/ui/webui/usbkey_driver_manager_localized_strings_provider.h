

#ifndef CHROME_BROWSER_UI_WEBUI_USBKEY_DRIVER_MANAGER_LOCALIZED_STRINGS_PROVIDER_H_
#define CHROME_BROWSER_UI_WEBUI_USBKEY_DRIVER_MANAGER_LOCALIZED_STRINGS_PROVIDER_H_

#ifndef OPENSSL_NO_GMTLS
namespace content {
class WebUIDataSource;
}

namespace usbkeydriver_manager {

// Adds the strings needed for the usbkeydriver_manager component to
// |html_source|. String ids correspond to ids in
// ui/webui/resources/cr_components/usbkeydriver_manager/.
void AddLocalizedStrings(content::WebUIDataSource* html_source);

}  // namespace usbkeydriver_manager

#endif //#OPENSSL_NO_GMTLS

#endif  // CHROME_BROWSER_UI_WEBUI_USBKEY_DRIVER_MANAGER_LOCALIZED_STRINGS_PROVIDER_H_
