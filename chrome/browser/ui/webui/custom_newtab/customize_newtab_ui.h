#ifndef CHROME_BROWSER_UI_WEBUI_CUSTOMIZE_NEWTAB_UI_H_
#define CHROME_BROWSER_UI_WEBUI_CUSTOMIZE_NEWTAB_UI_H_
#pragma once

#include "base/macros.h"
#include "content/public/browser/web_ui_controller.h"

// The WebUI for chrome://hello-world
class CustomizeNewTabUI : public content::WebUIController {
 public:
  explicit CustomizeNewTabUI(content::WebUI* web_ui);
  ~CustomizeNewTabUI() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(CustomizeNewTabUI);
};

#endif  // CHROME_BROWSER_UI_WEBUI_HELLO_WORLD_UI_H_