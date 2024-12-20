// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/child/npapi/webplugin_delegate_impl.h"

#include <gtk/gtk.h>
#include <gdk/gdk.h>
#if !defined(USE_GTK2)
#include <gtk/gtkx.h>
#endif
#include <gdk/gdkx.h>

#include <iostream>
#include <string>
#include <vector>
#include <cairo/cairo.h>
#include <cairo/cairo-xlib.h>

#include "content/child/npapi/plugin_instance.h"
#include "content/child/npapi/webplugin.h"
#include "content/public/common/content_constants.h"
#include "content/common/cursors/webcursor.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_mouse_event.h"
#include "third_party/blink/public/common/input/web_pointer_properties.h"
#include "third_party/blink/public/web/web_input_element.h"
#include "ui/gfx/blit.h"
#include "third_party/npapi/bindings/npapi_x11.h"
#include "third_party/npapi/bindings/npapi.h"
#include <X11/Xlib.h>
#include <X11/Xutil.h>

using blink::WebKeyboardEvent;
using blink::WebInputEvent;
using blink::WebMouseEvent;

namespace content {

WebPluginDelegateImpl::WebPluginDelegateImpl(
    WebPlugin* plugin,
    PluginInstance* instance)
    : windowed_handle_(0),
      windowed_did_set_window_(false),
      windowless_(false),
      plugin_(plugin),
      instance_(instance),
      windowless_shm_pixmap_(None),
      pixmap_(NULL),
      first_event_time_(-1.0),
      plug_(NULL),
      socket_(NULL),
      quirks_(0),
      handle_event_depth_(0),
      first_set_window_call_(true),
      plugin_has_focus_(false),
      has_webkit_focus_(false),
      containing_view_has_focus_(true),
      creation_succeeded_(false) {
  memset(&window_, 0, sizeof(window_));
  if (instance_->mime_type() == kFlashPluginSwfMimeType) {
    // Flash is tied to Firefox's whacky behavior with windowless plugins. See
    // comments in WindowlessPaint.
    // TODO(viettrungluu): PLUGIN_QUIRK_WINDOWLESS_NO_RIGHT_CLICK: Don't allow
    // right-clicks in windowless content since Flash 10.1 (initial release, at
    // least) hangs in that case. Remove this once Flash is fixed.
  #ifdef USE_UNIONTECH_NPAPI
    quirks_ |= PLUGIN_QUIRK_WINDOWLESS_INVALIDATE_AFTER_SET_WINDOW
        | PLUGIN_QUIRK_WINDOWLESS_NO_RIGHT_CLICK;
  #else
    quirks_ |= PLUGIN_QUIRK_WINDOWLESS_OFFSET_WINDOW_TO_DRAW
        | PLUGIN_QUIRK_WINDOWLESS_INVALIDATE_AFTER_SET_WINDOW
        | PLUGIN_QUIRK_WINDOWLESS_NO_RIGHT_CLICK;
  #endif
  }

  // TODO(evanm): I played with this for quite a while but couldn't
  // figure out a way to make Flash not crash unless I didn't call
  // NPP_SetWindow.
  // However, after piman's grand refactor of windowed plugins, maybe
  // this is no longer necessary.
#ifdef USE_UNIONTECH_NPAPI
  quirks_ |= PLUGIN_QUIRK_DONT_SET_NULL_WINDOW_HANDLE_ON_DESTROY;
#endif
}

WebPluginDelegateImpl::~WebPluginDelegateImpl() {
#ifdef USE_UNIONTECH_NPAPI
  // FetchedURL registe OnResourceFetched observer in the plugin thread,
  //if WebPluginDelegate be destructed be before fetch resource finish,
  //plugi thread will crash,so we remove the observer at delegate destructor.
  PluginThread::current()->RemovePluginResourceDispatcherDelegate(this);
#endif
  DestroyInstance();

  if (!windowless_)
    WindowedDestroyWindow();

  if (window_.ws_info) {
    // We only ever use ws_info as an NPSetWindowCallbackStruct.
    delete static_cast<NPSetWindowCallbackStruct*>(window_.ws_info);
  }

  if (pixmap_) {
    g_object_unref(pixmap_);
    pixmap_ = NULL;
  }
}

bool WebPluginDelegateImpl::PlatformInitialize() {
  gfx::PluginWindowHandle handle = windowless_ ? 0 : gtk_plug_get_id(GTK_PLUG(plug_));
  plugin_->SetWindow(handle);
  return true;
}

void WebPluginDelegateImpl::PlatformDestroyInstance() {
  // Nothing to do here.
}

void WebPluginDelegateImpl::Paint(cc::PaintCanvas* canvas, const gfx::Rect& rect) {}

void WebPluginDelegateImpl::Paint(SkCanvas* canvas, const gfx::Rect& rect) {
  LOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::Paint";
  if (!windowless_ /*|| !skia::SupportsPlatformPaint(canvas)*/)
    return;
#if 0
  skia::ScopedPlatformPaint scoped_platform_paint(canvas);
  cairo_t* context = scoped_platform_paint.GetPlatformSurface();
#else
  SkPixmap pixmap;
  skia::GetWritablePixels(canvas, &pixmap);
  DCHECK(pixmap.addr());
  // SkPixmap does not manage the lifetime of this pointer, so it remains
  // valid after the object goes out of scope. It will become invalid if
  // the canvas' backing is destroyed or a pending saveLayer() is resolved.
  cairo_t* context = nullptr;
  cairo_surface_t* surface = cairo_image_surface_create_for_data(
                                  (unsigned char*)pixmap.writable_addr32(0, 0),
                                  CAIRO_FORMAT_ARGB32,
                                  canvas->imageInfo().width(),
                                  canvas->imageInfo().height(),
                                  cairo_format_stride_for_width(CAIRO_FORMAT_ARGB32, canvas->imageInfo().width()));
  context = cairo_create(surface);
#endif
  WindowlessPaint(context, rect);
}

bool WebPluginDelegateImpl::WindowedCreatePlugin() {
  DCHECK(!windowed_handle_);
  DCHECK(!plug_);

  LOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::WindowedCreatePlugin";
  // NPP_GetValue() might write 4 bytes of data to this variable.  Don't use a
  // single byte bool, use an int instead and make sure it is initialized.
  int xembed = 0;
  NPError err = instance_->NPP_GetValue(NPPVpluginNeedsXEmbed, &xembed);
  if (err != NPERR_NO_ERROR || !xembed) {
    NOTIMPLEMENTED() << " windowed plugin but without xembed. "
      "See http://code.google.com/p/chromium/issues/detail?id=38229";
    return false;
  }

  // Passing 0 as the socket XID creates a plug without plugging it in a socket
  // yet, so that it can be latter added with gtk_socket_add_id().
  plug_ = gtk_plug_new(0);
  gtk_widget_show(plug_);
  socket_ = gtk_socket_new();
  gtk_widget_show(socket_);
  gtk_container_add(GTK_CONTAINER(plug_), socket_);
  gtk_widget_show_all(plug_);

  // Prevent the plug from being destroyed if the browser kills the container
  // window.
  g_signal_connect(plug_, "delete-event", G_CALLBACK(gtk_true), NULL);
  // Prevent the socket from being destroyed when the plugin removes itself.
  g_signal_connect(socket_, "plug_removed", G_CALLBACK(gtk_true), NULL);

  windowed_handle_ = gtk_socket_get_id(GTK_SOCKET(socket_));

  window_.window = reinterpret_cast<void*>(windowed_handle_);  
 
  if (!window_.ws_info) {
    window_.ws_info = new NPSetWindowCallbackStruct;
  }
  NPSetWindowCallbackStruct* extra = static_cast<NPSetWindowCallbackStruct*>(window_.ws_info);
  extra->type = NP_SETWINDOW;
#if defined(USE_GTK2)
  extra->display = GDK_DISPLAY();
  int screen = DefaultScreen(extra->display);
  extra->visual = DefaultVisual(extra->display, screen);
  extra->depth = DefaultDepth(extra->display, screen);
  extra->colormap = DefaultColormap(extra->display, screen);
#else
  extra->display = gdk_x11_get_default_xdisplay();
  int screen = DefaultScreen(gdk_x11_get_default_xdisplay());
  extra->visual = DefaultVisual(gdk_x11_get_default_xdisplay(), screen);
  extra->depth = DefaultDepth(gdk_x11_get_default_xdisplay(), screen);
  extra->colormap = DefaultColormap(gdk_x11_get_default_xdisplay(), screen);
#endif
  LOG(INFO) << "[NPAPI][GTK] PluginProcess WindowedCreatePlugin " << windowed_handle_; 
 
  return true;
}

void WebPluginDelegateImpl::WindowedDestroyWindow() {
  if (!windowless_)
    windowed_did_set_window_ = false;
  if (plug_) {
    plugin_->WillDestroyWindow(gtk_plug_get_id(GTK_PLUG(plug_)));

    gtk_widget_destroy(plug_);
    plug_ = NULL;
    socket_ = NULL;
    windowed_handle_ = 0;
  }
}

bool WebPluginDelegateImpl::WindowedReposition(
    const gfx::Rect& window_rect,
    const gfx::Rect& clip_rect) {
  if (window_rect == window_rect_ && clip_rect == clip_rect_)
    return false;

  window_rect_ = window_rect;
  clip_rect_ = clip_rect;

  return true;
}

void WebPluginDelegateImpl::WindowedSetWindow() {
  if (!instance_.get())
    return;

  if (!windowed_handle_) {
    NOTREACHED();
    return;
  }

  // See https://bugzilla.mozilla.org/show_bug.cgi?id=108347
  // If we call NPP_SetWindow with a <= 0 width or height, problems arise in
  // Flash (and possibly other plugins).
  // TODO(piman): the Mozilla code suggests that for the Java plugin, we should
  // still call NPP_SetWindow in that case. We need to verify that.
  // fix by hwb  [start] adapt for plugin when window height or width is zero result plugin failure
  if (window_rect_.width() < 0 || window_rect_.height() < 0) {
    return;
  }

  if(window_rect_.width() == 0){
    window_rect_.set_width(1);
  }

  if(window_rect_.height() == 0){
    window_rect_.set_height(1);
  }

  instance()->set_window_handle(windowed_handle_);

  DCHECK(!instance()->windowless());

  window_.clipRect.top = clip_rect_.y();
  window_.clipRect.left = clip_rect_.x();
  window_.clipRect.bottom = clip_rect_.y() + clip_rect_.height();
  window_.clipRect.right = clip_rect_.x() + clip_rect_.width();
  window_.height = window_rect_.height();
  window_.width = window_rect_.width();
  window_.x = window_rect_.x();
  window_.y = window_rect_.y();
  window_.type = NPWindowTypeWindow;

  LOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::WindowedSetWindow " << window_.clipRect.top
            << " " << window_.clipRect.left << " " << window_.clipRect.bottom << " " << window_.clipRect.right;

  LOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::WindowedSetWindow height:" << window_.height << " width:" << window_.width;
  LOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::WindowedSetWindow x:" << window_.x << " y:" << window_.y;
  LOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::WindowedSetWindow window:" << window_.window;
  LOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::WindowedSetWindow window_handle:" << windowed_handle_;
  // Reset this flag before entering the instance in case of side-effects.
  windowed_did_set_window_ = true;

  NPError err = instance()->NPP_SetWindow(&window_);
  DCHECK(err == NPERR_NO_ERROR);
}

void WebPluginDelegateImpl::WindowlessUpdateGeometry(
    const gfx::Rect& window_rect,
    const gfx::Rect& clip_rect) {
  // Only resend to the instance if the geometry has changed.
  if (window_rect == window_rect_ && clip_rect == clip_rect_)
    return;

  clip_rect_ = clip_rect;
  window_rect_ = window_rect;
  WindowlessSetWindow();
}

void WebPluginDelegateImpl::emptyPixmap(GdkPixmap* pixmap,double x, double y,
		 double width, double height) {
  cairo_t* cairo = gdk_cairo_create(pixmap);
  cairo_set_source_rgb(cairo, 0.f, 0.f, 0.f);
  cairo_rectangle (cairo, x, y, width, height);
  cairo_fill(cairo);
  cairo_destroy(cairo);
}

void WebPluginDelegateImpl::EnsurePixmapAtLeastSize(int width, int height) {
  DLOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::EnsurePixmapAtLeastSize width:" << width << " height:" << height;
  if (pixmap_) {
    gint cur_width, cur_height;
  #if defined(USE_GTK2)
    gdk_pixmap_get_size(pixmap_, &cur_width, &cur_height);
  #else
    cur_width = cairo_image_surface_get_width(pixmap_);
    cur_height = cairo_image_surface_get_height(pixmap_);
  #endif
    DLOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::EnsurePixmapAtLeastSize cur_width:" << cur_width << " cur_height:" << cur_height;
    if (cur_width >= width && cur_height >= height) {
      DLOG(WARNING) << "[NPAPI][GTK] WebPluginDelegateImpl::EnsurePixmapAtLeastSize return early";
      emptyPixmap(pixmap_, 0, 0, cur_width, cur_height);
      return;  // We are already the appropriate size.
    }

    // Otherwise, we need to recreate ourselves.
    g_object_unref(pixmap_);
    pixmap_ = NULL;
  }

  LOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::EnsurePixmapAtLeastSize start create cairo surface";
#if defined(USE_GTK2)
  // |sys_visual| is owned by gdk; we shouldn't free it.
  GdkVisual* sys_visual = gdk_visual_get_system();
  pixmap_ = gdk_pixmap_new(NULL,  // use width/height/depth params
                           std::max(1, width), std::max(1, height),
                           sys_visual->depth);
  // TODO(erg): Replace this with GdkVisual when we move to GTK3.
  GdkColormap* colormap = gdk_colormap_new(gdk_visual_get_system(),
                                           FALSE);
  gdk_drawable_set_colormap(pixmap_, colormap);
  // The GdkDrawable now owns the GdkColormap.
  g_object_unref(colormap);
  emptyPixmap(pixmap_, 0, 0,  std::max(1, width), std::max(1, height));
#else
  pixmap_ = cairo_image_surface_create(CAIRO_FORMAT_A1,  // use width/height/depth params
                          std::max(1, width), std::max(1, height));
#endif
  LOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::EnsurePixmapAtLeastSize finish create cairo surface";
}

#ifdef DEBUG_RECTANGLES
namespace {

// Draw a rectangle on a Cairo context.
// Useful for debugging various rectangles involved in drawing plugins.
void DrawDebugRectangle(cairo_t* cairo,
                        const gfx::Rect& rect,
                        float r, float g, float b) {
  cairo_set_source_rgba(cairo, r, g, b, 0.5);
  cairo_rectangle(cairo, rect.x(), rect.y(),
                  rect.width(), rect.height());
  cairo_stroke(cairo);
}

}  // namespace
#endif

static void BlitContextToContext(cairo_t* dst_context,
                          const gfx::Rect& dst_rect,
                          cairo_t* src_context,
                          const gfx::Point& src_origin) {
#if defined(OS_WIN)
  BitBlt(dst_context, dst_rect.x(), dst_rect.y(),
         dst_rect.width(), dst_rect.height(),
         src_context, src_origin.x(), src_origin.y(), SRCCOPY);
#elif defined(OS_MACOSX)
  // Only translations and/or vertical flips in the source context are
  // supported; more complex source context transforms will be ignored.

  // If there is a translation on the source context, we need to account for
  // it ourselves since CGBitmapContextCreateImage will bypass it.
  Rect src_rect(src_origin, dst_rect.size());
  CGAffineTransform transform = CGContextGetCTM(src_context);
  bool flipped = fabs(transform.d + 1) < 0.0001;
  CGFloat delta_y = flipped ? CGBitmapContextGetHeight(src_context) -
                              transform.ty
                            : transform.ty;
  src_rect.Offset(transform.tx, delta_y);

  base::ScopedCFTypeRef<CGImageRef> src_image(
      CGBitmapContextCreateImage(src_context));
  base::ScopedCFTypeRef<CGImageRef> src_sub_image(
      CGImageCreateWithImageInRect(src_image, src_rect.ToCGRect()));
  CGContextDrawImage(dst_context, dst_rect.ToCGRect(), src_sub_image);
#elif defined(OS_LINUX)
  // Only translations in the source context are supported; more complex
  // source context transforms will be ignored.
  cairo_save(dst_context);
  double surface_x = src_origin.x();
  double surface_y = src_origin.y();
  cairo_user_to_device(src_context, &surface_x, &surface_y);
  cairo_set_source_surface(dst_context, cairo_get_target(src_context),
                           dst_rect.x()-surface_x, dst_rect.y()-surface_y);
  cairo_rectangle(dst_context, dst_rect.x(), dst_rect.y(),
                  dst_rect.width(), dst_rect.height());
  cairo_clip(dst_context);
  cairo_paint(dst_context);
  cairo_restore(dst_context);
#else
  NOTIMPLEMENTED();
#endif
}

void WebPluginDelegateImpl::WindowlessPaint(cairo_t* context,
                                            const gfx::Rect& damage_rect) {
  // Compare to:
  // http://mxr.mozilla.org/firefox/source/layout/generic/nsObjectFrame.cpp:
  // nsPluginInstanceOwner::Renderer::NativeDraw().

  DCHECK(context);
  DLOG(INFO) << "[NPAPI][GTK] WebPluginDelegateImpl::WindowlessPaint";
  // TODO(darin): we should avoid calling NPP_SetWindow here since it may
  // cause page layout to be invalidated.

  // The actual dirty region is just the intersection of the plugin window and
  // the clip window with the damage region. However, the plugin wants to draw
  // relative to the containing window's origin, so our pixmap must be from the
  // window's origin down to the bottom-right edge of the dirty region.
  //
  // Typical case:
  // X-----------------------------------+-----------------------------+
  // |                                   |                             |
  // |    pixmap     +-------------------+                             |
  // |               |   damage          |                window       |
  // |               |                   |                             |
  // |           +---+-------------------+-------------+               |
  // |           |   |                   |   clip      |               |
  // |       +---+---+-------------------+----------+  |               |
  // |       |   |   |                   |          |  |               |
  // |       |   |   | draw              |          |  |               |
  // |       |   |   |                   |          |  |               |
  // +-------+---+---+-------------------+----------+--+               |
  // |       |       |                   |          |                  |
  // |       |       +-------------------+          |                  |
  // |       |                                      |                  |
  // |       |        plugin                        |                  |
  // |       +--------------------------------------+                  |
  // |                                                                 |
  // |                                                                 |
  // +-----------------------------------------------------------------+
  // X = origin
  //
  // NPAPI doesn't properly define which coordinates each of
  // - window.clipRect, window.x and window.y in the SetWindow call
  // - x and y in GraphicsExpose HandleEvent call
  // are relative to, nor does it define what the pixmap is relative to.
  //
  // Any sane values for them just don't work with the flash plugin. Firefox
  // has some interesting behavior. Experiments showed that:
  // - window.clipRect is always in the same space as window.x and window.y
  // - in the first SetWindow call, or when scrolling, window.x and window.y are
  // the coordinates of the plugin relative to the window.
  // - whenever only a part of the plugin is drawn, Firefox issues a SetWindow
  // call before each GraphicsExpose event, that sets the drawing origin to
  // (0, 0) as if the plugin was scrolled to be partially out of the view. The
  // GraphicsExpose event has coordinates relative to the "window" (assuming
  // that virtual scroll). The pixmap is also relative to the window. It always
  // sets the clip rect to the draw rect.
  //
  // Attempts to deviate from that makes Flash render at the wrong place in the
  // pixmap, or render the wrong pixels.
  //
  // Flash plugin:
  // X-----------------------------------------------------------------+
  // |                                                                 |
  // |               +-------------------+        "real" window        |
  // |               |   damage          |                             |
  // |               |                   |                             |
  // |           +---+-------------------+-------------+               |
  // |           |   |                   | "real" clip |               |
  // |       +---+---O===================#==========#==#===============#
  // |       |   |   H draw              |          |  |               H
  // |       |   |   H = pixmap          |          |  |               H
  // |       |   |   H = "apparent" clip |          |  |               H
  // |       +   +---#-------------------+----------+--+               H
  // |       |       H                   |          |                  H
  // |       |       H-------------------+          |                  H
  // |       |       H                              |                  H
  // |       |       H  plugin                      |                  H
  // |       +-------#------------------------------+                  H
  // |               H                                                 H
  // |               H                  "apparent" window              H
  // +---------------#=================================================#
  // X = "real" origin
  // O = "apparent" origin
  // "real" means as seen by Chrome
  // "apparent" means as seen by the plugin.

  gfx::Rect draw_rect = gfx::IntersectRects(window_rect_, damage_rect);

  // clip_rect_ is relative to the plugin
  gfx::Rect clip_rect_window = clip_rect_;
  clip_rect_window.Offset(window_rect_.x(), window_rect_.y());
  draw_rect.Intersect(clip_rect_window);

  // These offsets represent by how much the view is shifted to accomodate
  // Flash (the coordinates of X relative to O in the diagram above).
  int offset_x = 0;
  int offset_y = 0;
  if (quirks_ & PLUGIN_QUIRK_WINDOWLESS_OFFSET_WINDOW_TO_DRAW) {
    offset_x = -draw_rect.x();
    offset_y = -draw_rect.y();
    window_.clipRect.top = 0;
    window_.clipRect.left = 0;
    window_.clipRect.bottom = draw_rect.height();
    window_.clipRect.right = draw_rect.width();
    window_.height = window_rect_.height();
    window_.width = window_rect_.width();
    window_.x = window_rect_.x() - draw_rect.x();
    window_.y = window_rect_.y() - draw_rect.y();
    window_.type = NPWindowTypeDrawable;
    DCHECK(window_.ws_info);
    NPError err = instance()->NPP_SetWindow(&window_);
    DCHECK_EQ(err, NPERR_NO_ERROR);
  }

  gfx::Rect pixmap_draw_rect = draw_rect;
  pixmap_draw_rect.Offset(offset_x, offset_y);

  gfx::Rect pixmap_rect(0, 0,
                        pixmap_draw_rect.right(),
                        pixmap_draw_rect.bottom());

  // Construct the paint message, targeting the pixmap.
  NPEvent np_event = {0};
  XGraphicsExposeEvent& event = np_event.xgraphicsexpose;
  event.type = GraphicsExpose;
  event.x = pixmap_draw_rect.x();
  event.y = pixmap_draw_rect.y();
  event.width = pixmap_draw_rect.width();
  event.height = pixmap_draw_rect.height();
#if defined(USE_GTK2)
  event.display = GDK_DISPLAY();
#else
  event.display = gdk_x11_get_default_xdisplay();
#endif

  if (0 && windowless_shm_pixmap_ != None) {
    Pixmap pixmap = None;
    GC xgc = NULL;
    Display* display = event.display;
    gfx::Rect plugin_draw_rect = draw_rect;

    // Make plugin_draw_rect relative to the plugin window.
    plugin_draw_rect.Offset(-window_rect_.x(), -window_rect_.y());

    // In case the drawing area does not start with the plugin window origin,
    // we can not let the plugin directly draw over the shared memory pixmap.
    if (plugin_draw_rect.x() != pixmap_draw_rect.x() ||
        plugin_draw_rect.y() != pixmap_draw_rect.y()) {
      pixmap = XCreatePixmap(display, windowless_shm_pixmap_,
                             std::max(1, pixmap_rect.width()),
                             std::max(1, pixmap_rect.height()),
                             DefaultDepth(display, DefaultScreen(display)));
      xgc = XCreateGC(display, windowless_shm_pixmap_, 0, NULL);
      // Copy the current image into the pixmap, so the plugin can draw over it.
      XCopyArea(display, windowless_shm_pixmap_, pixmap, xgc,
                plugin_draw_rect.x(), plugin_draw_rect.y(),
                pixmap_draw_rect.width(), pixmap_draw_rect.height(),
                pixmap_draw_rect.x(), pixmap_draw_rect.y());

      event.drawable = pixmap;
    } else {
      event.drawable = windowless_shm_pixmap_;
    }

    // Tell the plugin to paint into the pixmap.
    // base::StatsRate plugin_paint("Plugin.Paint");
    // base::StatsScope<base::StatsRate> scope(plugin_paint);
    instance()->NPP_HandleEvent(&np_event);

    if (pixmap != None) {
      // Copy the rendered image pixmap back into the shm pixmap
      // and thus the drawing buffer.
      XCopyArea(display, pixmap, windowless_shm_pixmap_, xgc,
                pixmap_draw_rect.x(), pixmap_draw_rect.y(),
                pixmap_draw_rect.width(), pixmap_draw_rect.height(),
                plugin_draw_rect.x(), plugin_draw_rect.y());
      XSync(display, FALSE);
      if (xgc)
        XFreeGC(display, xgc);
      XFreePixmap(display, pixmap);
    } else {
      XSync(display, FALSE);
    }
  } else {

    gfx::Rect draw_back_rect{draw_rect.x() - window_rect_.x(),
        draw_rect.y() - window_rect_.y(),
        draw_rect.width(), draw_rect.height()};

    EnsurePixmapAtLeastSize(pixmap_rect.width(), pixmap_rect.height());

  #if defined(USE_GTK2)
    event.drawable = GDK_PIXMAP_XID(pixmap_);
  #else
    event.drawable = cairo_xlib_surface_get_drawable(pixmap_);
  #endif

    instance()->NPP_HandleEvent(&np_event);

    cairo_t* cairo4_writeback = gdk_cairo_create(pixmap_);
    BlitContextToContext(context, draw_back_rect,
      cairo4_writeback, pixmap_draw_rect.origin());
    cairo_destroy(cairo4_writeback);


#ifdef DEBUG_RECTANGLES
    // Draw some debugging rectangles.
    // Pixmap rect = blue.
    DrawDebugRectangle(context, pixmap_rect, 0, 0, 1);
    // Drawing rect = red.
    DrawDebugRectangle(context, draw_rect, 1, 0, 0);
#endif
  }
}

void WebPluginDelegateImpl::WindowlessSetWindow() {
  if (!instance())
    return;

  if (window_rect_.IsEmpty())  // wait for geometry to be set.
    return;

  DCHECK(instance()->windowless());
  // Mozilla docs say that this window param is not used for windowless
  // plugins; rather, the window is passed during the GraphicsExpose event.
  DCHECK_EQ(window_.window, static_cast<void*>(NULL));

  window_.clipRect.top = clip_rect_.y() + window_rect_.y();
  window_.clipRect.left = clip_rect_.x() + window_rect_.x();
  window_.clipRect.bottom = clip_rect_.y() + clip_rect_.height() + window_rect_.y();
  window_.clipRect.right = clip_rect_.x() + clip_rect_.width() + window_rect_.x();
  window_.height = window_rect_.height();
  window_.width = window_rect_.width();
  window_.x = window_rect_.x();
  window_.y = window_rect_.y();
  window_.type = NPWindowTypeDrawable;

  if (!window_.ws_info)
    window_.ws_info = new NPSetWindowCallbackStruct;
  NPSetWindowCallbackStruct* extra = static_cast<NPSetWindowCallbackStruct*>(window_.ws_info);
#if defined(USE_GTK2)
  extra->display = GDK_DISPLAY();
  int screen = DefaultScreen(GDK_DISPLAY());
  extra->visual = DefaultVisual(GDK_DISPLAY(), screen);
  extra->depth = DefaultDepth(GDK_DISPLAY(), screen);
  extra->colormap = DefaultColormap(GDK_DISPLAY(), screen);
#else
  extra->display = gdk_x11_get_default_xdisplay();
  int screen = DefaultScreen(gdk_x11_get_default_xdisplay());
  extra->visual = DefaultVisual(gdk_x11_get_default_xdisplay(), screen);
  extra->depth = DefaultDepth(gdk_x11_get_default_xdisplay(), screen);
  extra->colormap = DefaultColormap(gdk_x11_get_default_xdisplay(), screen);
#endif

  LOG(INFO) << "[NPAPI] WebPluginDelegateImpl::WindowlessSetWindow -> NPP_SetWindow";
  NPError err = instance()->NPP_SetWindow(&window_);
  DCHECK(err == NPERR_NO_ERROR);
  if (quirks_ & PLUGIN_QUIRK_WINDOWLESS_INVALIDATE_AFTER_SET_WINDOW) {
    // After a NPP_SetWindow, Flash cancels its timer that generates the
    // invalidates until it gets a paint event, but doesn't explicitly call
    // NPP_InvalidateRect.
    plugin_->InvalidateRect(clip_rect_);
  }
}

bool WebPluginDelegateImpl::PlatformSetPluginHasFocus(bool focused) {
  DCHECK(instance()->windowless());

  NPEvent np_event = {0};
  XFocusChangeEvent& event = np_event.xfocus;
  event.type = focused ? FocusIn : FocusOut;
#if defined(USE_GTK2)
  event.display = GDK_DISPLAY();
#else
  event.display = gdk_x11_get_default_xdisplay();
#endif
  // Same values as Firefox. .serial and .window stay 0.
  event.mode = -1;
  event.detail = NotifyDetailNone;
  instance()->NPP_HandleEvent(&np_event);
  return true;
}

// Converts a WebInputEvent::Modifiers bitfield into a
// corresponding X modifier state.
static int GetXModifierState(int modifiers) {
  int x_state = 0;
  if (modifiers & WebInputEvent::kControlKey)
    x_state |= ControlMask;
  if (modifiers & WebInputEvent::kShiftKey)
    x_state |= ShiftMask;
  if (modifiers & WebInputEvent::kAltKey)
    x_state |= Mod1Mask;
  if (modifiers & WebInputEvent::kMetaKey)
    x_state |= Mod2Mask;
  if (modifiers & WebInputEvent::kLeftButtonDown)
    x_state |= Button1Mask;
  if (modifiers & WebInputEvent::kMiddleButtonDown)
    x_state |= Button2Mask;
  if (modifiers & WebInputEvent::kRightButtonDown)
    x_state |= Button3Mask;
  // TODO(piman@google.com): There are other modifiers, e.g. Num Lock, that
  // should be set (and Firefox does), but we didn't keep the information in
  // the WebKit event.
  return x_state;
}

static bool NPEventFromWebMouseEvent(const WebMouseEvent& event,
                                     Time timestamp,
                                     NPEvent* np_event) {
  np_event->xany.display = GDK_DISPLAY();
  // NOTE: Firefox keeps xany.serial and xany.window as 0.

  int modifier_state = GetXModifierState(event.GetModifiers());

  Window root = GDK_ROOT_WINDOW();
  switch (event.GetType()) {
    case WebInputEvent::kMouseMove: {
      np_event->type = MotionNotify;
      XMotionEvent& motion_event = np_event->xmotion;
      motion_event.root = root;
      motion_event.time = timestamp;
      motion_event.x = event.PositionInWidget().x();
      motion_event.y = event.PositionInWidget().y();
      motion_event.x_root = event.PositionInScreen().x();
      motion_event.y_root = event.PositionInScreen().y();
      motion_event.state = modifier_state;
      motion_event.is_hint = NotifyNormal;
      motion_event.same_screen = True;
      break;
    }
    case WebInputEvent::kMouseLeave:
    case WebInputEvent::kMouseEnter: {
      if (event.GetType() == WebInputEvent::kMouseEnter) {
        np_event->type = EnterNotify;
      } else {
        np_event->type = LeaveNotify;
      }
      XCrossingEvent& crossing_event = np_event->xcrossing;
      crossing_event.root = root;
      crossing_event.time = timestamp;
      crossing_event.x = event.PositionInWidget().x();
      crossing_event.y = event.PositionInWidget().y();
      crossing_event.x_root = event.PositionInScreen().x();
      crossing_event.y_root = event.PositionInScreen().y();
      crossing_event.mode = -1;  // This is what Firefox sets it to.
      crossing_event.detail = NotifyDetailNone;
      crossing_event.same_screen = True;
      // TODO(piman@google.com): set this to the correct value. Firefox does. I
      // don't know where to get the information though, we get focus
      // notifications, but no unfocus.
      crossing_event.focus = 0;
      crossing_event.state = modifier_state;
      break;
    }
    case WebInputEvent::kMouseUp:
    case WebInputEvent::kMouseDown: {
      if (event.GetType() == WebInputEvent::kMouseDown) {
        np_event->type = ButtonPress;
      } else {
        np_event->type = ButtonRelease;
      }
      XButtonEvent& button_event = np_event->xbutton;
      button_event.root = root;
      button_event.time = timestamp;
      button_event.x = event.PositionInWidget().x();
      button_event.y = event.PositionInWidget().y();
      button_event.x_root = event.PositionInScreen().x();
      button_event.y_root = event.PositionInScreen().y();
      button_event.state = modifier_state;
      switch (event.button) {
        case blink::WebPointerProperties::Button::kLeft:
          button_event.button = Button1;
          break;
        case blink::WebPointerProperties::Button::kMiddle:
          button_event.button = Button2;
          break;
        case blink::WebPointerProperties::Button::kRight:
          button_event.button = Button3;
          break;
        default:
          NOTREACHED();
      }
      button_event.same_screen = True;
      break;
    }
    default:
      NOTREACHED();
      return false;
  }
  return true;
}

static bool NPEventFromWebKeyboardEvent(const WebKeyboardEvent& event,
                                        Time timestamp,
                                        NPEvent* np_event) {
#if defined(USE_GTK2)
  np_event->xany.display = GDK_DISPLAY();
#else
  np_event->xany.display = gdk_x11_get_default_xdisplay();
#endif
  // NOTE: Firefox keeps xany.serial and xany.window as 0.

  switch (event.GetType()) {
    case WebKeyboardEvent::kKeyDown:
      np_event->type = KeyPress;
      break;
    case WebKeyboardEvent::kKeyUp:
      np_event->type = KeyRelease;
      break;
    default:
      NOTREACHED();
      return false;
  }
  XKeyEvent& key_event = np_event->xkey;
  key_event.send_event = False;
#if defined(USE_GTK2)
  key_event.display = GDK_DISPLAY();
#else
  key_event.display = gdk_x11_get_default_xdisplay();
#endif
  // NOTE: Firefox keeps xany.serial and xany.window as 0.
  // TODO(piman@google.com): is this right for multiple screens ?
  key_event.root = DefaultRootWindow(key_event.display);
  key_event.time = timestamp;
  // NOTE: We don't have the correct information for x/y/x_root/y_root. Firefox
  // doesn't have it either, so we pass the same values.
  key_event.x = 0;
  key_event.y = 0;
  key_event.x_root = -1;
  key_event.y_root = -1;
  key_event.state = GetXModifierState(event.GetModifiers());
  key_event.keycode = event.native_key_code;
  key_event.same_screen = True;
  return true;
}

static bool NPEventFromWebInputEvent(const WebInputEvent& event,
                                     Time timestamp,
                                     NPEvent* np_event) {
  switch (event.GetType()) {
    case WebInputEvent::kMouseMove:
    case WebInputEvent::kMouseLeave:
    case WebInputEvent::kMouseEnter:
    case WebInputEvent::kMouseDown:
    case WebInputEvent::kMouseUp:
      return NPEventFromWebMouseEvent(
          *static_cast<const WebMouseEvent*>(&event), timestamp, np_event);
    case WebInputEvent::kKeyDown:
    case WebInputEvent::kKeyUp:
      return NPEventFromWebKeyboardEvent(
          *static_cast<const WebKeyboardEvent*>(&event), timestamp, np_event);
    default:
      return false;
  }
}

bool WebPluginDelegateImpl::PlatformHandleInputEvent(
    const blink::WebInputEvent& event, ui::Cursor* cursor_info) {
  if (first_event_time_ < 0.0)
    first_event_time_ = event.TimeStamp().ToInternalValue();
  Time timestamp = static_cast<Time>(
      (event.TimeStamp().ToInternalValue() - first_event_time_) * 1.0e3);
  NPEvent np_event = {0};
  if (!NPEventFromWebInputEvent(event, timestamp, &np_event)) {
    return false;
  }
  // See comment about PLUGIN_QUIRK_WINDOWLESS_NO_RIGHT_CLICK in constructor.
  if (windowless_ &&
      (quirks_ & PLUGIN_QUIRK_WINDOWLESS_NO_RIGHT_CLICK) &&
      (np_event.type == ButtonPress || np_event.type == ButtonRelease) &&
      (np_event.xbutton.button == Button3)) {
    return false;
  }

  bool ret = instance()->NPP_HandleEvent(&np_event) != 0;

  // Flash always returns false, even when the event is handled.
  return ret;
}

}  // namespace content
