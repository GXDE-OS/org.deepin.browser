// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_RENDERER_HOST_GTK_PLUGIN_CONTAINER_MANAGER_H_
#define CONTENT_BROWSER_RENDERER_HOST_GTK_PLUGIN_CONTAINER_MANAGER_H_

#include <map>
#include <memory>

#include <gtk/gtk.h>

#include "base/memory/scoped_refptr.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/views/widget/npapi_plugin_mask.h"

#if defined(USE_GTK2)
typedef struct _GtkWidget GtkWidget;
typedef struct _GdkDrawable GdkWindow;
#endif
typedef struct _XDisplay Display;
typedef struct _GtkSocket GtkSocket;
typedef struct _GdkEventExpose GdkEventExpose;
typedef void* gpointer;
typedef struct _cairo cairo_t;

namespace views {
class Widget;
}

namespace content {
struct WebPluginGeometry;

class MaskArea;

// Helper class that creates and manages plugin containers (GtkSocket).
class GtkPluginContainerManager:
    public views::NpapiPluginMaskObserver {
 public:
  GtkPluginContainerManager();
  ~GtkPluginContainerManager() override;


  // Creates a new plugin container, for a given plugin XID.
  // parent_window represent a xwindow.
  GtkWidget *CreatePluginContainer(gfx::PluginWindowHandle id, unsigned long parent_window);
  
 // show all the plugins in the relative webpage
  void Show();

 // hide all the plugins in the relative webpage
  void Hide();

  // Destroys a plugin container, given the plugin XID.
  void DestroyPluginContainer(gfx::PluginWindowHandle id);

  // Takes an update from WebKit about a plugin's position and side and moves
  // the plugin accordingly.
  void MovePluginContainer(const WebPluginGeometry& move);

  // NpapiPluginMaskObserver implement
  void MoveRect(const views::Widget*, const gfx::Rect& new_rect) override;
  void ShowRect(const views::Widget*, const gfx::Rect& new_rect) override;
  void HideRect(const views::Widget*, const gfx::Rect& new_rect) override;
  void AddWidgetObserver(views::Widget* widget) override;
  void DeleteWidgetObserver(views::Widget* widget) override;
  void RenderProcessGone(int status, int error_code){}

  void ShowReparentPlugin(unsigned long new_parent_window, bool actived);

 public:
  // parent's window title changed
  void OnWindowTitleChanged(const std::string& title){}

  void OnWindowActiveStatusChanged(bool actived);

  // called when position of browser window changed
  void OnWindowPositionChanged(const gfx::Rect& page_rect){}


//private:
//  void DidCreatePluginContainer(gfx::PluginWindowHandle id);

private:
  // A map that associates plugin containers to the plugin XID.
  typedef struct {
    GtkSocket* plug_container_socket = 0;
    GtkWidget* plug_container_window = 0;
    GtkWidget* fix_container = 0;
    ::Display* child_display = 0;
    unsigned long child_window = 0;
    unsigned long parent_window = 0;
    gfx::Rect window_rect;  
    gfx::Rect clip_rect;
    //begin  @huangwenbing: fix bug#62986
    bool visible = true;
    //end  @huangwenbing: fix bug#62986
    std::unique_ptr<MaskArea> mask_area_;
  } PluginContainer;

  void ShowPluginContainer(PluginContainer* plugin_container);
  void HidePluginContainer(const PluginContainer& plugin_container);

  // Maps a plugin XID to the corresponding container widget.
  GtkWidget* MapIDToWidget(gfx::PluginWindowHandle id);

  // Maps a plugin XID to the corresponding container widget.
  GtkWidget* MapIDToToplevel(gfx::PluginWindowHandle id);

  // Maps a container widget to the corresponding plugin XID.
  gfx::PluginWindowHandle MapToplevelToID(GtkWidget* widget);

  // Callback for when the plugin container gets realized, at which point it
  // plugs the plugin XID.
  static void RealizeCallback(GtkWidget *widget, void *user_data);

private:
  friend class MaskArea;

  // Parent of the plugin containers.
  GtkWidget* host_widget_;

  std::string title_;

  typedef std::map<gfx::PluginWindowHandle, PluginContainer* > PluginContainerMap;
  PluginContainerMap plugin_container_map_;

  // widget who is interested in GtkPluginContainerManager
  std::vector<views::Widget *> widget_observers_;

  // the rects of widgets who were occluding the webpage that contains plugins
  std::map<const views::Widget *, gfx::Rect> occluded_rects;

  // only after plugin creating ,the Mask could make sense
  bool is_plugin_created_ = false;  

  bool is_plugin_active = false;
};
}  // namespace content

#endif  // CONTENT_BROWSER_RENDERER_HOST_GTK_PLUGIN_CONTAINER_MANAGER_H_
