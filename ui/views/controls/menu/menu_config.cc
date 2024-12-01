// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/views/controls/menu/menu_config.h"

#include "base/macros.h"
#include "base/no_destructor.h"
#include "ui/views/controls/menu/menu_controller.h"
#include "ui/views/controls/menu/menu_item_view.h"

#include "uos/dbus_thread_manager.h"
#include "uos/dde/dde_vm_compositing_client.h"

namespace views {

MenuConfig::MenuConfig() {
  Init();
}

MenuConfig::~MenuConfig() = default;

int MenuConfig::CornerRadiusForMenu(const MenuController* controller) const {
  //wangjuna: disable set border corner radius, use fixed value 18, 2020-07-25, --start
#if 0
  if (controller && controller->use_touchable_layout())
    return touchable_corner_radius;
  if (controller && (controller->IsCombobox() || controller->IsContextMenu()))
    return auxiliary_corner_radius;
  return corner_radius;
#else
  bool isDdeCompositingEnable = dbus::uos::DBusThreadManager::Get()->GetDdeVMCompositingClient()->getCompositingEnabled();
  if(isDdeCompositingEnable){
    return 18;
  }
  return 0;
#endif
  //wangjuna: disable set border corner radius, use fixed value 18, 2020-07-25, --end
}

bool MenuConfig::ShouldShowAcceleratorText(const MenuItemView* item,
                                           base::string16* text) const {
  if (!show_accelerators || !item->GetDelegate() || !item->GetCommand())
    return false;
  ui::Accelerator accelerator;
  if (!item->GetDelegate()->GetAccelerator(item->GetCommand(), &accelerator))
    return false;
  if (item->GetMenuController() && item->GetMenuController()->IsContextMenu() &&
      !show_context_menu_accelerators) {
    return false;
  }
  *text = accelerator.GetShortcutText();
  return true;
}

// static
const MenuConfig& MenuConfig::instance() {
  static base::NoDestructor<MenuConfig> instance;
  return *instance;
}

}  // namespace views
