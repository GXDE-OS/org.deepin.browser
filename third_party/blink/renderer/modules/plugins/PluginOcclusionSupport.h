/*
    Copyright (C) 2011 Robert Hogan <robert@roberthogan.net>.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public License
    along with this library; see the file COPYING.LIB.  If not, write to
    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA 02110-1301, USA.
*/

#ifndef Use_Uniontech_PluginOcclusionSupport
#define Use_Uniontech_PluginOcclusionSupport

// #include "third_party/blink/renderer/modules/modules_export.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
class Element;
class LocalFrameView;
class IntRect;

CORE_EXPORT void getPluginOcclusions(Element*,
                                        LocalFrameView* parentFrameView,
                                        const IntRect& frameRect,
                                        Vector<IntRect>& occlusions);

}  // namespace blink

#endif  // Use_Uniontech_PluginOcclusionSupport
