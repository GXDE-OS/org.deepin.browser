// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/renderer_host/npapi/gtk_plugin_container_manager.h"

#include <gdk/gdkx.h>

#if defined(USE_GTK2)
#include <gdk/gdk.h>
#else
#include <gtk/gtkx.h>
#endif

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/shape.h>

#include "base/logging.h"
#include "chrome/browser/ui/session_crashed_bubble.h"
#include "content/common/webplugin_geometry.h"
#include "ui/aura/window.h"
#include "ui/base/x/x11_util.h"
#include "ui/views/widget/widget.h"

#define PRINT_VAL(value) PRINT_VAL_MSG(value,"")
#define PRINT_VAL_MSG(value, message) \
  LOG(WARNING) << __FUNCTION__ <<"  "#value" : " << value <<", " message

//#define PLUGIN_CONTAINER_DEBUG 1

namespace content {

class MaskArea {
  public:
    MaskArea(GtkPluginContainerManager::PluginContainer* plugin_container,
             GtkPluginContainerManager* plugin_container_manager);
    ~MaskArea();

    void MoveRect(const views::Widget* id, const gfx::Rect& new_rect);
    void ShowRect(const views::Widget* id, const gfx::Rect& new_rect);
    void HideRect(const views::Widget* id, const gfx::Rect& new_rect);
    void SetViewPortRect(const gfx::Rect &rect);
    Pixmap MaskPixmap(){ return mask_pixmap_; }

    // mask's clipped area is moved(resized)
    // use this to reduce the computation
    void MoveClippedMaskArea(const gfx::Rect &old_rect, const gfx::Rect &new_rect);

    // recalculate the bits representing the area that is specified by rect_id
    // is_clip represent whether the rect is to be clipped
    void CalculateClip(const gfx::Rect &rect, bool is_clip);

    void CreatePixmap();
    void ClearPixmap();

    void Repaint();
    void OnUpdateClipRect();

  public:
    // the intersect rects of plugin and webpage's popups
    std::map<const views::Widget*, gfx::Rect> intersect_rects_;
    gfx::Rect view_port_rect_;
    Pixmap mask_pixmap_ = 0;

    int black_pixel_ = 0;
    int white_pixel_ = 0;

    GC pixmap_gc_ = NULL;

    GtkPluginContainerManager::PluginContainer* plugin_container_ = 0;
    const GtkPluginContainerManager* plugin_container_manager_ = 0;
};

void MaskArea::MoveRect(const views::Widget* id, const gfx::Rect& new_rect) {

  PRINT_VAL(new_rect.ToString());

  if(new_rect.IsEmpty()) {
    HideRect(id, new_rect);
    return ;
  }

  auto iter = intersect_rects_.find(id);
  if(iter != intersect_rects_.end()) {
    iter->second = gfx::IntersectRects(new_rect, view_port_rect_);
    Repaint();
    OnUpdateClipRect();
  } else {
    ShowRect(id, new_rect);
  }
}

void MaskArea::ShowRect(const views::Widget* id, const gfx::Rect& new_rect) {

  PRINT_VAL(new_rect.ToString());

  auto iter = intersect_rects_.find(id);

  // in case that some widgets hold empty bounds when
  // showing the first time
  if(new_rect.IsEmpty()) {
    if(iter != intersect_rects_.end()) {
      HideRect(id, iter->second);
      intersect_rects_.erase(iter);
    }
    return ;
  }

  if(iter == intersect_rects_.end()) {
    gfx::Rect rect = new_rect;
    gfx::Rect intersect_rect = gfx::IntersectRects(rect, view_port_rect_);

    if( !intersect_rect.IsEmpty() ) {
      intersect_rects_[id] = intersect_rect;
    } else {
      LOG(WARNING) << "intersect rect of viewport and the popup is empty";
      return ;
    }
  }

  Repaint();

  OnUpdateClipRect();
}

void MaskArea::HideRect(const views::Widget* id, const gfx::Rect& ) {

  auto iter = intersect_rects_.find(id);
  if (iter == intersect_rects_.end() )
    return ;

  gfx::Rect intersect_rect = iter->second;

  PRINT_VAL(intersect_rect.ToString());

  intersect_rects_.erase(iter);
  Repaint();

  // tell manager to remask its plugin windows
  OnUpdateClipRect();
}


MaskArea::MaskArea(GtkPluginContainerManager::PluginContainer* plugin_container,
                   GtkPluginContainerManager* plugin_container_manager)
  : plugin_container_(plugin_container),
  plugin_container_manager_(plugin_container_manager){
  Display *display = gfx::GetXDisplay();
  black_pixel_ = BlackPixel(display, DefaultScreen(display)) & (~1);
  white_pixel_ = WhitePixel(display, DefaultScreen(display)) | 1;
}


MaskArea::~MaskArea() {
  ClearPixmap();
  intersect_rects_.clear();
}


void MaskArea::CalculateClip(const gfx::Rect &rect, bool is_clip) {
  gfx::Rect intersect_rect = rect;
  if (intersect_rect.IsEmpty()) {
    LOG(WARNING) << "intersect rect is empty ";
    return ;
  }

  PRINT_VAL(intersect_rect.ToString());

  int x = intersect_rect.x() - view_port_rect_.x();
  DCHECK(x >= 0);

  int y = intersect_rect.y() - view_port_rect_.y();
  DCHECK(y >= 0);

  int foreground_pixel = is_clip? black_pixel_: white_pixel_;
  Display *display = plugin_container_->child_display;
  XSetForeground(display, pixmap_gc_, foreground_pixel);
  XFillRectangle(display, mask_pixmap_, pixmap_gc_,
                 x, y,
                 intersect_rect.width(), intersect_rect.height());
}

void MaskArea::CreatePixmap() {
  ClearPixmap();

  Display* display = plugin_container_->child_display;
  mask_pixmap_ = XCreatePixmap(display, plugin_container_->child_window,
      view_port_rect_.width(), view_port_rect_.height(),  1);

  LOG(INFO) << "[NPAPI] MaskArea::CreatePixmap: " << view_port_rect_.width() << " " << view_port_rect_.height();

  XGCValues shape_xgcv;
  shape_xgcv.background = white_pixel_;
  shape_xgcv.foreground = black_pixel_;

  pixmap_gc_ = XCreateGC(display, mask_pixmap_, GCForeground | GCBackground, &shape_xgcv);
  XSetForeground(display, pixmap_gc_, white_pixel_);
  XFillRectangle(display, mask_pixmap_, pixmap_gc_, 0, 0,
                 view_port_rect_.width(), view_port_rect_.height());
}

void MaskArea::ClearPixmap() {
    Display *display = plugin_container_->child_display;
    if(mask_pixmap_) {
      XFreePixmap(display, mask_pixmap_);
      mask_pixmap_ = 0;
    }
    if(pixmap_gc_) {
      XFreeGC(display, pixmap_gc_);
      pixmap_gc_ = 0;
    }
}

void MaskArea::Repaint() {
  Display* display = plugin_container_->child_display;
  XSetForeground(display, pixmap_gc_, white_pixel_);
  XFillRectangle(display, mask_pixmap_, pixmap_gc_, 0, 0,
                 view_port_rect_.width(), view_port_rect_.height());

  LOG(INFO) << "[NPAPI] MaskArea::Repaint: " << view_port_rect_.width() << " " << view_port_rect_.height();

  for(auto &intersect_pair: intersect_rects_) {
    CalculateClip(intersect_pair.second, true);
  }
}

void MaskArea::OnUpdateClipRect() {
  if(!MaskPixmap()) return ;

  gfx::Point origin = {0, 0};

  LOG(INFO) << "[NPAPI] MaskArea::OnUpdateClipRect";

  XShapeCombineMask(plugin_container_->child_display,
                    plugin_container_->child_window,
                    ShapeBounding, origin.x(), origin.y(),
                    plugin_container_->mask_area_->MaskPixmap(), ShapeSet);
  gtk_widget_queue_draw(plugin_container_->plug_container_window);
}

void MaskArea::SetViewPortRect(const gfx::Rect &rect) {
  PRINT_VAL(view_port_rect_.ToString());
  gfx::Rect old_rect = view_port_rect_;
  view_port_rect_ = rect;
  if (view_port_rect_.IsEmpty()) {
    ClearPixmap();
    LOG(WARNING) << "[NPAPI] MaskArea::SetViewPortRect view_port_rect_ is empty";
    return ;
  }

  bool is_damage_area_changed = false;

  // pick up the occluding widgets' rects from manager,
  // and use them to calclulate intersect rects,
  // then show the calclulated result
  for(const auto &occluded_rect_pair:
      plugin_container_manager_->occluded_rects) {
    gfx::Rect intersect =
        gfx::IntersectRects(view_port_rect_,
        occluded_rect_pair.second);

    auto iter = intersect_rects_.find(occluded_rect_pair.first);
    if(iter == intersect_rects_.end()) {
      if(!intersect.IsEmpty()) {
        intersect_rects_[occluded_rect_pair.first] =
            intersect;
        is_damage_area_changed = true;
      }
    } else if(intersect.IsEmpty()) {
      intersect_rects_.erase(iter);
      is_damage_area_changed = true;
    } else if (intersect != iter->second) {
      iter->second = intersect;
      is_damage_area_changed = true;
    } else if (intersect == iter->second) {
      PRINT_VAL_MSG(intersect.ToString(), " not damaged");
    }
  }

  bool is_view_port_changed = (view_port_rect_.size() != old_rect.size());
  if (is_damage_area_changed) {
    if ( is_view_port_changed ) {
      CreatePixmap();
      OnUpdateClipRect();
    }

    LOG(WARNING) << "[NPAPI] MaskArea::SetViewPortRect 1";
    Repaint();
    OnUpdateClipRect();
  } else {
    if ( is_view_port_changed ) {
      LOG(WARNING) << "[NPAPI] MaskArea::SetViewPortRect 2";
      CreatePixmap();
      Repaint();
      OnUpdateClipRect();
    }
    LOG(WARNING) << "[NPAPI] MaskArea::SetViewPortRect 3";
  }
}

void MaskArea::MoveClippedMaskArea(const gfx::Rect &old_rect,
                                   const gfx::Rect &new_rect) {
  CalculateClip(old_rect, false);
  CalculateClip(new_rect, true);

  // tell manager to remask
  OnUpdateClipRect();
}

GtkPluginContainerManager::GtkPluginContainerManager() {
    host_widget_ = NULL;
}

GtkPluginContainerManager::~GtkPluginContainerManager() {
  for (auto *widget: widget_observers_) {
    if(widget && widget->GetNpapiPuginMask())
      widget->GetNpapiPuginMask()->DeleteObserver(this);
  }
}

GtkWidget* GtkPluginContainerManager::CreatePluginContainer(
    gfx::PluginWindowHandle id, unsigned long parent_window) {

  DCHECK(id != 0 && parent_window != 0);

  LOG(INFO) << "[NPAPI][GTK] GtkPluginContainerManager::CreatePluginContainer";
  GtkWidget * widget_parent = (GtkWidget*)gtk_window_new(GTK_WINDOW_TOPLEVEL);
  GtkSocket * socket_parent = (GtkSocket *)gtk_socket_new();
  GtkWidget * widget = (GtkWidget* )socket_parent;

  gtk_window_set_title(GTK_WINDOW(widget_parent), "Plugin Container");

  GtkWidget *fix_container = gtk_fixed_new();
  gtk_container_add(GTK_CONTAINER(widget_parent), fix_container);
  gtk_widget_set_size_request(widget, -1, -1);
  gtk_fixed_put((GtkFixed*)fix_container, widget, 0, 0);

  PluginContainer* plugin_container = new PluginContainer;
  plugin_container->plug_container_socket = socket_parent;
  plugin_container->plug_container_window = widget_parent;
  plugin_container->fix_container = fix_container;
  plugin_container->parent_window = parent_window;

  auto it = plugin_container_map_.find(id);
  if( it != plugin_container_map_.end() )
    DestroyPluginContainer(id);
  plugin_container_map_[id] = plugin_container;

  // The Realize callback is responsible for adding the plug into the socket.
  // The reason is 2-fold:
  // - the plug can't be added until the socket is realized, but this may not
  // happen until the socket is attached to a top-level window, which isn't the
  // case for background tabs.
  // - when dragging tabs, the socket gets unrealized, which breaks the XEMBED
  // connection. We need to make it again when the tab is reattached, and the
  // socket gets realized again.

  // Note, the RealizeCallback relies on the plugin_window_to_widget_map_ to
  // have the mapping.
  g_signal_connect(widget_parent, "realize",
                   G_CALLBACK(RealizeCallback), this);

  LOG(INFO) << "[NPAPI] BrowserProcess OnCreatePluginContainer plugin id : " << id;
  LOG(INFO) << "[NPAPI] BrowserProcess OnCreatePluginContainer parent_window : " << parent_window;
  gtk_widget_show_all(plugin_container->plug_container_window);
  is_plugin_created_ = true;
  return widget;
}

void GtkPluginContainerManager::ShowReparentPlugin(unsigned long new_parent_window, bool actived) {
  LOG(INFO) << "[NPAPI] GtkPluginContainerManager::ShowReparentPlugin START";
  if (plugin_container_map_.size() == 0) {
    LOG(WARNING) << "[NPAPI] GtkPluginContainerManager::ShowReparentPlugin RETURN 1";
    return;
  }

  unsigned long old_parent = plugin_container_map_.begin()->second->parent_window;
  unsigned long new_parent = new_parent_window;
  if (new_parent == old_parent) {
    LOG(WARNING) << "[NPAPI] GtkPluginContainerManager::ShowReparentPlugin RETURN 2";
    return;
  }

  std::map<gfx::PluginWindowHandle, PluginContainer* >::iterator it = plugin_container_map_.begin();
  for (; it != plugin_container_map_.end(); it++) {
    PluginContainer* plugin_container = static_cast<PluginContainer*>(it->second);

    plugin_container->parent_window = new_parent_window;

    LOG(INFO) << "[NPAPI] GtkPluginContainerManager::ShowReparentPlugin LOOP";

#if defined(USE_GTK2)
    GdkDisplay* gdk_display = gdk_window_get_display(plugin_container->plug_container_window->window);
    XID widget_parent_id = GDK_WINDOW_XID(plugin_container->plug_container_window->window);
#else
    GdkDisplay* gdk_display = gdk_window_get_display(gtk_widget_get_window(plugin_container->plug_container_window));
    XID widget_parent_id = GDK_WINDOW_XID(gtk_widget_get_window(plugin_container->plug_container_window));
#endif    
    Display* x_display = gdk_x11_display_get_xdisplay(gdk_display);    
    plugin_container->child_display = x_display;
    plugin_container->child_window = widget_parent_id;

    HidePluginContainer(*plugin_container);

    XReparentWindow(x_display, widget_parent_id, plugin_container->parent_window, 0, 0);

    if (actived) {
      ShowPluginContainer(plugin_container);
    }

    gfx::Rect view_port = {
       plugin_container->window_rect.x() + plugin_container->clip_rect.x(),
       plugin_container->window_rect.y() + plugin_container->clip_rect.y(),
       plugin_container->clip_rect.width(),
       plugin_container->clip_rect.height()
    };

    plugin_container->mask_area_->SetViewPortRect(view_port);

    if(new_parent_window == 0)
      plugin_container->parent_window = old_parent;

  }
  LOG(INFO) << "[NPAPI] GtkPluginContainerManager::ShowReparentPlugin END";
}

void GtkPluginContainerManager::Show() {
  LOG(INFO) << "[NPAPI] GtkPluginContainerManager::Show";
  for(auto & pair: plugin_container_map_) {
    ShowPluginContainer(pair.second);
  }
}

void GtkPluginContainerManager::Hide() {
  for(auto & pair: plugin_container_map_) {
    HidePluginContainer(*pair.second);
  }
}

void GtkPluginContainerManager::DestroyPluginContainer(
    gfx::PluginWindowHandle id) {

  auto destroy_plugin_container = [&](PluginContainerMap::iterator iter){
    if ( iter->second ) {
        auto *plugin_container = iter->second;
        if ( plugin_container->plug_container_socket ) {
          gtk_widget_destroy((GtkWidget *)plugin_container->plug_container_socket);
          plugin_container->plug_container_socket = nullptr;
        }
        if ( plugin_container->plug_container_window ) {
          gtk_widget_destroy(plugin_container->plug_container_window);
          plugin_container->plug_container_window = nullptr;
        }
        if ( plugin_container->mask_area_ )
          plugin_container->mask_area_.reset();
        delete plugin_container;
    }
    plugin_container_map_.erase(iter);
  };

  if (id == 0) {
    for (auto iter = plugin_container_map_.begin(); !plugin_container_map_.empty();
         iter = plugin_container_map_.begin()) {
      destroy_plugin_container(iter);
    }
  } else {
    auto iter = plugin_container_map_.find(id);
    if(iter == plugin_container_map_.end())
      return;

    destroy_plugin_container(iter);
  }
  is_plugin_created_ = plugin_container_map_.empty();
}

void GtkPluginContainerManager::MovePluginContainer(
    const WebPluginGeometry& move) {

  auto iter = plugin_container_map_.find(move.window);
  if(iter == plugin_container_map_.end()) {
    LOG(INFO) << move.window << "  plugin is not found";
    return ;
  }
  auto* plugin_container = iter->second;
  plugin_container->visible = move.visible;
  if (!move.visible || move.clip_rect.IsEmpty()) {
    HidePluginContainer(*iter->second);    
    return;
  }

  if (!move.rects_valid)
    return; 

  plugin_container->window_rect = move.window_rect;
  plugin_container->clip_rect = move.clip_rect;

  ShowPluginContainer(plugin_container);

  gfx::Rect view_port = {
    move.window_rect.x() + move.clip_rect.x(),
    move.window_rect.y() + move.clip_rect.y(),
    move.clip_rect.width(),
    move.clip_rect.height()
  };  

  plugin_container->mask_area_->SetViewPortRect(view_port);
}

void GtkPluginContainerManager::MoveRect(const views::Widget* id,
                                         const gfx::Rect &new_rect) {
  if( !id || !id->IsVisible() )
    return ;

  // hide the old occluded_rects[id] and show the new_rect
  // then update occluded_rects[id]
  auto iter = occluded_rects.find(id);

  if(iter != occluded_rects.end()) {
    for(auto &plugin_container_pair: plugin_container_map_) {
      plugin_container_pair.second->mask_area_->MoveRect(id, new_rect);
    }

    if(new_rect.IsEmpty())
      occluded_rects.erase(iter);
    else
      iter->second = new_rect;
  } else {
    ShowRect(id, new_rect);
  }
}

void GtkPluginContainerManager::ShowRect(const views::Widget* id, const gfx::Rect &new_rect) {
  // occluded_rects[id] is not exist
  // or occluded_rects[id] is invalid
  occluded_rects[id] = new_rect;
  for(auto &plugin_container_pair: plugin_container_map_){
    plugin_container_pair.second->mask_area_->ShowRect(id, new_rect);
    //ShowReparentPlugin(0,true);
  }

}

void GtkPluginContainerManager::HideRect(const views::Widget* id, const gfx::Rect &) {
  // hide the old rect indexed by id
  auto iter = occluded_rects.find(id);

  gfx::Rect rect;
  if(iter != occluded_rects.end()) {
    rect = iter->second;
    for(auto &plugin_container_pair: plugin_container_map_)
      plugin_container_pair.second->mask_area_->HideRect(id, rect);
    occluded_rects.erase(iter);
  } else
    return ;
}

void GtkPluginContainerManager::AddWidgetObserver(views::Widget *widget){
  auto iter = std::find(widget_observers_.begin(), widget_observers_.end(), widget);
  if(iter == widget_observers_.end())
      widget_observers_.push_back(widget);
}

void GtkPluginContainerManager::DeleteWidgetObserver(views::Widget *widget) {
  auto iter = std::find(widget_observers_.begin(), widget_observers_.end(), widget);
  if(iter != widget_observers_.end())
    widget_observers_.erase(iter);
}

GtkWidget* GtkPluginContainerManager::MapIDToWidget(
    gfx::PluginWindowHandle id) {
  auto iter = plugin_container_map_.find(id);
  if (iter != plugin_container_map_.end()) {
    GtkWidget* socket = (GtkWidget* )(iter->second->plug_container_socket);
    return socket;
  }

  LOG(ERROR) << "Request for widget host for unknown window id " << id;
  return NULL;
}

GtkWidget* GtkPluginContainerManager::MapIDToToplevel(
    gfx::PluginWindowHandle id) {
  auto iter = plugin_container_map_.find(id);
  if (iter != plugin_container_map_.end())
    return iter->second->plug_container_window;

  LOG(ERROR) << "Request for widget host for unknown window id " << id;

  return NULL;
}

gfx::PluginWindowHandle GtkPluginContainerManager::MapToplevelToID(
     GtkWidget* widget) {
    for( auto & plugin_container: plugin_container_map_ ) {
      if( plugin_container.second->plug_container_window == widget )
          return plugin_container.first;
  }

  LOG(ERROR) << "Request for id for unknown widget";
  return 0;
}

void GtkPluginContainerManager::OnWindowActiveStatusChanged(bool actived) {
  is_plugin_active = actived;
  actived? Show(): Hide();
}

void GtkPluginContainerManager::ShowPluginContainer(
    PluginContainer *plugin_container) {
  // fix by hwb #62986 ---begin
  if (!plugin_container->visible)
    return;

  if (!is_plugin_active)
    return;
  // fix by hwb #62986 ---end

  LOG(INFO) << "[NPAPI] GtkPluginContainerManager::ShowPluginContainer";
  PRINT_VAL(plugin_container->clip_rect.ToString());
  PRINT_VAL(plugin_container->window_rect.ToString());

  if (plugin_container->clip_rect.IsEmpty() && plugin_container->window_rect.IsEmpty()) {
    return;
  }

  if (plugin_container->child_display && plugin_container->child_window && plugin_container->plug_container_socket) {
    //when plugin scroll to the top and over the range of browser view, we should
    //set the plugin top-left coordinate as negative number. this can clip the top
    //of  plugin by it's parent window.
    gtk_fixed_move((GtkFixed*)plugin_container->fix_container,
        (GtkWidget*)plugin_container->plug_container_socket,
        plugin_container->clip_rect.x()>0 ? -plugin_container->clip_rect.x(): 0 ,
        plugin_container->clip_rect.y()>0 ? -plugin_container->clip_rect.y(): 0);
    gtk_widget_set_size_request((GtkWidget*)plugin_container->plug_container_socket,
        plugin_container->window_rect.width(), plugin_container->window_rect.height());

    // leiyuanxiang , modify , bug (55663) , 2020/12/18 --start
    int x = plugin_container->window_rect.x() + plugin_container->clip_rect.x();
    int y = plugin_container->window_rect.y() + plugin_container->clip_rect.y();
    gtk_window_move(GTK_WINDOW(plugin_container->plug_container_window),x,y);
    // leiyuanxiang , modify , bug (55663) , 2020/12/18 --end

    XResizeWindow(gfx::GetXDisplay(),
        plugin_container->child_window,
        plugin_container->clip_rect.width(),
        plugin_container->clip_rect.height());

    gtk_widget_show_all(plugin_container->plug_container_window);
  }
}

void GtkPluginContainerManager::HidePluginContainer(
    const GtkPluginContainerManager::PluginContainer &plugin_container) {
  LOG(INFO) << "[NPAPI] GtkPluginContainerManager::HidePluginContainer";
#if defined(USE_GTK2)
  gtk_widget_hide_all(plugin_container.plug_container_window);      
#else  
  gtk_widget_hide(plugin_container.plug_container_window);
#endif  
}

// static
void GtkPluginContainerManager::RealizeCallback(GtkWidget* widget,
                                                void* user_data) {
  GtkPluginContainerManager* plugin_container_manager =
      static_cast<GtkPluginContainerManager*>(user_data);

  LOG(INFO) << "[NPAPI] BrowserProcess OnCreatePluginContainer::RealizeCallback START";

  gfx::PluginWindowHandle id = plugin_container_manager->MapToplevelToID(widget);
  if(id == 0)
    return ;

  auto iter = plugin_container_manager->plugin_container_map_.find(id);
  if(iter == plugin_container_manager->plugin_container_map_.end())
    return ;

  auto* plugin_container = iter->second;
  // add plugin window to socket which is from plugin process
  if(plugin_container->plug_container_socket) {
    #if defined(PLUGIN_CONTAINER_DEBUG)
      GtkWidget *window_debug = gtk_plug_new(gtk_socket_get_id(GTK_SOCKET(plugin_container->plug_container_socket)));
      GtkWidget *button_ = gtk_button_new();
      gtk_widget_show(button_);
      gtk_widget_set_tooltip_text(button_, "Button widget");
      gtk_widget_set_size_request(button_, 100, 100);
      gtk_container_add(GTK_CONTAINER(window_debug), button_);
      gtk_widget_show (window_debug);
    #else
      gtk_socket_add_id(plugin_container->plug_container_socket, id);
      LOG(INFO) << "[NPAPI] BrowserProcess OnCreatePluginContainer::RealizeCallback START id:" << id;
    #endif
  }

#if defined(USE_GTK2)
  GdkDisplay* gdk_display = gdk_window_get_display(widget->window);
  XID widget_parent_id = GDK_WINDOW_XID(widget->window);
  gtk_widget_hide_all(plugin_container->plug_container_window);
#else
  GdkDisplay* gdk_display = gdk_window_get_display(gtk_widget_get_window(widget));
  XID widget_parent_id = GDK_WINDOW_XID(gtk_widget_get_window(widget));
  gtk_widget_hide(plugin_container->plug_container_window);
#endif  
  Display* x_display = gdk_x11_display_get_xdisplay(gdk_display);  
  plugin_container->child_display = x_display;
  plugin_container->child_window = widget_parent_id;

  LOG(INFO) << "[NPAPI] BrowserProcess OnCreatePluginContainer::RealizeCallback child_window:" << plugin_container->child_window;
  LOG(INFO) << "[NPAPI] BrowserProcess OnCreatePluginContainer::RealizeCallback parent_window:" << plugin_container->parent_window;
  XReparentWindow(x_display, widget_parent_id, plugin_container->parent_window, 0, 0);

  LOG(INFO) << "[NPAPI] BrowserProcess OnCreatePluginContainer::RealizeCallback END";

  iter->second->mask_area_ = std::make_unique<MaskArea>(plugin_container, plugin_container_manager);

  if (SessionCrashedBubble::GetSessionCrashedBubbleWidget() && !SessionCrashedBubble::GetSessionCrashedBubbleWidget()->IsClosed()) {
    SessionCrashedBubble::ReplaySessionCrashedBubbleWidget();
  }
}

}  // namespace content
