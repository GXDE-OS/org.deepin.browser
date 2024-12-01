// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_VIEW_MESSAGES_H_
#define CONTENT_COMMON_VIEW_MESSAGES_H_

// IPC messages for page rendering.

#include <stddef.h>
#include <stdint.h>

#include <set>
#include <string>
#include <vector>

#include "base/optional.h"
#include "base/process/process.h"
#include "base/strings/string16.h"
#include "build/build_config.h"
#include "cc/input/touch_action.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "components/viz/common/quads/compositor_frame.h"
#include "components/viz/common/resources/shared_bitmap.h"
#include "content/common/common_param_traits_macros.h"
#include "content/common/content_export.h"
#include "content/common/content_param_traits.h"
#include "content/common/frame_replication_state.h"
#include "content/common/navigation_gesture.h"
#include "content/common/webplugin_geometry.h"
#include "content/public/common/common_param_traits.h"
#include "content/public/common/menu_item.h"
#include "content/public/common/page_state.h"
#include "content/public/common/page_zoom.h"
#include "content/public/common/referrer.h"
#include "content/public/common/three_d_api_types.h"
#include "ipc/ipc_channel_handle.h"
#include "ipc/ipc_message_macros.h"
#include "media/base/audio_parameters.h"
#include "media/base/channel_layout.h"
#include "media/base/ipc/media_param_traits.h"
#include "net/base/network_change_notifier.h"
#include "ppapi/buildflags/buildflags.h"
#include "third_party/blink/public/mojom/manifest/display_mode.mojom.h"
#include "third_party/blink/public/mojom/renderer_preferences.mojom.h"
#include "third_party/blink/public/platform/web_text_autosizer_page_info.h"
#include "ui/base/ime/text_input_type.h"
#include "ui/gfx/color_space.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/vector2d.h"
#include "ui/gfx/geometry/vector2d_f.h"
#include "ui/gfx/ipc/color/gfx_param_traits.h"
#include "ui/gfx/ipc/gfx_param_traits.h"
#include "ui/gfx/ipc/skia/gfx_skia_param_traits.h"
#include "ui/native_theme/native_theme.h"

#if defined(OS_MACOSX)
#include "third_party/blink/public/platform/mac/web_scrollbar_theme.h"
#endif

#if defined(USE_UNIONTECH_NPAPI)
#include "content/common/webplugin_geometry.h"
#endif

#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT CONTENT_EXPORT

#define IPC_MESSAGE_START ViewMsgStart

IPC_ENUM_TRAITS_MAX_VALUE(content::MenuItem::Type, content::MenuItem::TYPE_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(content::NavigationGesture,
                          content::NavigationGestureLast)
IPC_ENUM_TRAITS_MIN_MAX_VALUE(content::PageZoom,
                              content::PageZoom::PAGE_ZOOM_OUT,
                              content::PageZoom::PAGE_ZOOM_IN)
IPC_ENUM_TRAITS_MAX_VALUE(content::ThreeDAPIType,
                          content::THREE_D_API_TYPE_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(ui::TextInputType, ui::TEXT_INPUT_TYPE_MAX)

#if defined(OS_MACOSX)
IPC_ENUM_TRAITS_MAX_VALUE(blink::ScrollerStyle, blink::kScrollerStyleOverlay)
#endif

IPC_ENUM_TRAITS_MAX_VALUE(ui::NativeTheme::SystemThemeColor,
                          ui::NativeTheme::SystemThemeColor::kMaxValue)

#if defined(USE_UNIONTECH_NPAPI)
IPC_STRUCT_TRAITS_BEGIN(content::WebPluginGeometry)
  IPC_STRUCT_TRAITS_MEMBER(window)
  IPC_STRUCT_TRAITS_MEMBER(window_rect)
  IPC_STRUCT_TRAITS_MEMBER(clip_rect)
  IPC_STRUCT_TRAITS_MEMBER(cutout_rects)
  IPC_STRUCT_TRAITS_MEMBER(rects_valid)
  IPC_STRUCT_TRAITS_MEMBER(visible)
IPC_STRUCT_TRAITS_END()
IPC_STRUCT_BEGIN(ViewHostMsg_UpdateRect_Params)
  // New window locations for plugin child windows.
  IPC_STRUCT_MEMBER(std::vector<content::WebPluginGeometry>,
                    plugin_window_moves)
IPC_STRUCT_END()
// This message starts/stop monitoring the input method status of the focused
// edit control of a renderer process.
// Parameters
// * is_active (bool)
//   Indicates if an input method is active in the browser process.
//   The possible actions when a renderer process receives this message are
//   listed below:
//     Value Action
//     true  Start sending IPC message ViewHostMsg_ImeUpdateTextInputState
//           to notify the input method status of the focused edit control.
//     false Stop sending IPC message ViewHostMsg_ImeUpdateTextInputState.
IPC_MESSAGE_ROUTED1(ViewMsg_SetInputMethodActive,
                    bool /* is_active */)

// This message sends a string being composed with an input method.
IPC_MESSAGE_ROUTED4(
    ViewMsg_ImeSetComposition,
    base::string16, /* text */
    std::vector<blink::WebImeTextSpan>, /* underlines */
    int, /* selectiont_start */
    int /* selection_end */)

// This message confirms an ongoing composition.
IPC_MESSAGE_ROUTED3(ViewMsg_ImeConfirmComposition,
                    base::string16 /* text */,
                    gfx::Range /* replacement_range */,
                    bool /* keep_selection */)

// Update NPAPI plugin.
IPC_MESSAGE_ROUTED1(ViewHostMsg_UpdateRect, ViewHostMsg_UpdateRect_Params)
// A renderer sends this when it needs a browser-side widget for
// hosting a windowed plugin. id is the XID of the plugin window, for which
// the container is created.
IPC_SYNC_MESSAGE_ROUTED1_0(ViewHostMsg_CreatePluginContainer,
                           gfx::PluginWindowHandle /* id */)

// Destroy a plugin container previously created using CreatePluginContainer.
// id is the XID of the plugin window corresponding to the container that is
// to be destroyed.
IPC_SYNC_MESSAGE_ROUTED1_0(ViewHostMsg_DestroyPluginContainer,
                           gfx::PluginWindowHandle /* id */)
#endif

IPC_STRUCT_TRAITS_BEGIN(content::MenuItem)
  IPC_STRUCT_TRAITS_MEMBER(label)
  IPC_STRUCT_TRAITS_MEMBER(tool_tip)
  IPC_STRUCT_TRAITS_MEMBER(type)
  IPC_STRUCT_TRAITS_MEMBER(action)
  IPC_STRUCT_TRAITS_MEMBER(rtl)
  IPC_STRUCT_TRAITS_MEMBER(has_directional_override)
  IPC_STRUCT_TRAITS_MEMBER(enabled)
  IPC_STRUCT_TRAITS_MEMBER(checked)
  IPC_STRUCT_TRAITS_MEMBER(submenu)
IPC_STRUCT_TRAITS_END()

// Messages sent from the browser to the renderer.

// This passes a set of webkit preferences down to the renderer.
IPC_MESSAGE_ROUTED1(ViewMsg_UpdateWebPreferences,
                    content::WebPreferences)

// Used to notify the render-view that we have received a target URL. Used
// to prevent target URLs spamming the browser.
IPC_MESSAGE_ROUTED0(ViewMsg_UpdateTargetURL_ACK)

// Notification that a move or resize renderer's containing window has
// started.
IPC_MESSAGE_ROUTED0(ViewMsg_MoveOrResizeStarted)

#if BUILDFLAG(ENABLE_PLUGINS)
// Reply to ViewHostMsg_OpenChannelToPpapiBroker
// Tells the renderer that the channel to the broker has been created.
IPC_MESSAGE_ROUTED2(ViewMsg_PpapiBrokerChannelCreated,
                    base::ProcessId /* broker_pid */,
                    IPC::ChannelHandle /* handle */)

// Reply to ViewHostMsg_RequestPpapiBrokerPermission.
// Tells the renderer whether permission to access to PPAPI broker was granted
// or not.
IPC_MESSAGE_ROUTED1(ViewMsg_PpapiBrokerPermissionResult,
                    bool /* result */)
#endif

// -----------------------------------------------------------------------------
// Messages sent from the renderer to the browser.

// These two messages are sent to the parent RenderViewHost to display a widget
// that was created by CreateWidget/CreateFullscreenWidget. |route_id| refers
// to the id that was returned from the corresponding Create message above.
// |initial_rect| is in screen coordinates.
IPC_MESSAGE_ROUTED2(ViewHostMsg_ShowWidget,
                    int /* route_id */,
                    gfx::Rect /* initial_rect */)

// Message to show a full screen widget.
IPC_MESSAGE_ROUTED1(ViewHostMsg_ShowFullscreenWidget,
                    int /* route_id */)

// Sent from an inactive renderer for the browser to route to the active
// renderer, instructing it to close.
IPC_MESSAGE_ROUTED0(ViewHostMsg_RouteCloseEvent)

// Notifies the browser that we want to show a destination url for a potential
// action (e.g. when the user is hovering over a link).
IPC_MESSAGE_ROUTED1(ViewHostMsg_UpdateTargetURL,
                    GURL)

IPC_MESSAGE_ROUTED0(ViewHostMsg_Focus)

// Get the list of proxies to use for |url|, as a semicolon delimited list
// of "<TYPE> <HOST>:<PORT>" | "DIRECT".
IPC_SYNC_MESSAGE_CONTROL1_2(ViewHostMsg_ResolveProxy,
                            GURL /* url */,
                            bool /* result */,
                            std::string /* proxy list */)

#if BUILDFLAG(ENABLE_PLUGINS)
// A renderer sends this to the browser process when it wants to access a PPAPI
// broker. In contrast to FrameHostMsg_OpenChannelToPpapiBroker, this is called
// for every connection.
// The browser will respond with ViewMsg_PpapiBrokerPermissionResult.
IPC_MESSAGE_ROUTED3(ViewHostMsg_RequestPpapiBrokerPermission,
                    int /* routing_id */,
                    GURL /* document_url */,
                    base::FilePath /* plugin_path */)

IPC_SYNC_MESSAGE_CONTROL1_1(ViewHostMsg_GetPlugins,
    bool /* refresh*/,
    std::vector<content::WebPluginInfo> /* plugins */)
#endif  // BUILDFLAG(ENABLE_PLUGINS)

// When the renderer needs the browser to transfer focus cross-process on its
// behalf in the focus hierarchy. This may focus an element in the browser ui or
// a cross-process frame, as appropriate.
IPC_MESSAGE_ROUTED1(ViewHostMsg_TakeFocus,
                    bool /* reverse */)

IPC_MESSAGE_ROUTED1(
    ViewHostMsg_NotifyTextAutosizerPageInfoChangedInLocalMainFrame,
    blink::WebTextAutosizerPageInfo /* page_info */)

// Adding a new message? Stick to the sort order above: first platform
// independent ViewMsg, then ifdefs for platform specific ViewMsg, then platform
// independent ViewHostMsg, then ifdefs for platform specific ViewHostMsg.

#endif  // CONTENT_COMMON_VIEW_MESSAGES_H_
