/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/exported/PluginOcclusionSupport.h"

#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/frame/frame_view.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
// This file provides a utility function to support rendering certain elements
// above plugins.

namespace blink {

static void getObjectStack(const LayoutObject* ro,
                           Vector<const LayoutObject*>* roStack) {
  roStack->clear();
  while (ro) {
    roStack->Append(ro);
    ro = ro->Parent();
  }
}

// Returns true if stack1 is at or above stack2
static bool iframeIsAbovePlugin(
    const Vector<const LayoutObject*>& iframeZstack,
    const Vector<const LayoutObject*>& pluginZstack) {
  for (size_t i = 0; i < iframeZstack.size() && i < pluginZstack.size(); i++) {
    // The root is at the end of these stacks. We want to iterate
    // root-downwards so we index backwards from the end.
    const LayoutObject* ro1 = iframeZstack[iframeZstack.size() - 1 - i];
    const LayoutObject* ro2 = pluginZstack[pluginZstack.size() - 1 - i];

    if (ro1 != ro2) {
      // When we find nodes in the stack that are not the same, then
      // we've found the nodes just below the lowest comment ancestor.
      // Determine which should be on top.

      // See if z-index determines an order.
      if (ro1->Style() && ro2->Style()) {
        int z1 = ro1->Style()->ZIndex();
        int z2 = ro2->Style()->ZIndex();
        if (z1 > z2)
          return true;
        if (z1 < z2)
          return false;
      }

      // If the plugin does not have an explicit z-index it stacks behind the
      // iframe.  This is for maintaining compatibility with IE.
      if (!ro2->IsPositioned()) {
        // The 0'th elements of these LayoutObject arrays represent the plugin
        // node and the iframe.
        const LayoutObject* pluginLayoutObject = pluginZstack[0];
        const LayoutObject* iframeLayoutObject = iframeZstack[0];

        if (pluginLayoutObject->Style() && iframeLayoutObject->Style()) {
          if (pluginLayoutObject->Style()->ZIndex() >
              iframeLayoutObject->Style()->ZIndex())
            return false;
        }
        return true;
      }

      // Inspect the document order. Later order means higher stacking.
      const LayoutObject* parent = ro1->Parent();
      if (!parent)
        return false;
      DCHECK(parent == ro2->Parent());

      for (const LayoutObject* ro = parent->SlowFirstChild(); ro;
           ro = ro->NextSibling()) {
        if (ro == ro1)
          return false;
        if (ro == ro2)
          return true;
      }
      DCHECK(false);  // We should have seen ro1 and ro2 by now.
      return false;
    }
  }
  return true;
}

static bool intersectsRect(const LayoutObject* renderer, const IntRect& rect) {
  return renderer->AbsoluteBoundingBoxRect().Intersects(
             rect) &&
         (!renderer->Style() ||
          renderer->Style()->Visibility() == EVisibility::kVisible);
}

static void addToOcclusions(const LayoutBox* renderer,
                            Vector<IntRect>& occlusions) {
  occlusions.Append(IntRect(RoundedIntPoint(renderer->PhysicalLocation()),
                            FlooredIntSize(renderer->Size())));
}

static void addTreeToOcclusions(const LayoutObject* renderer,
                                const IntRect& frameRect,
                                Vector<IntRect>& occlusions) {
  if (!renderer)
    return;
  if (renderer->IsBox() && intersectsRect(renderer, frameRect))
    addToOcclusions(ToLayoutBox(renderer), occlusions);
  for (LayoutObject* child = renderer->SlowFirstChild(); child;
       child = child->NextSibling())
    addTreeToOcclusions(child, frameRect, occlusions);
}

static const Element* topLayerAncestor(const Element* element) {
  while (element && !element->IsInTopLayer())
    element = element->ParentOrShadowHostElement();
  return element;
}

// Return a set of rectangles that should not be overdrawn by the
// plugin ("cutouts"). This helps implement the "iframe shim"
// technique of overlaying a windowed plugin with content from the
// page. In a nutshell, iframe elements should occlude plugins when
// they occur higher in the stacking order.
void getPluginOcclusions(Element* element,
                         LocalFrameView* parentFrameView,
                         const IntRect& frameRect,
                         Vector<IntRect>& occlusions) {
  LayoutObject* pluginNode = element->GetLayoutObject();
  DCHECK(pluginNode);
  if (!pluginNode->Style())
    return;
  Vector<const LayoutObject*> pluginZstack;
  Vector<const LayoutObject*> iframeZstack;
  getObjectStack(pluginNode, &pluginZstack);

  for (Frame* child = parentFrameView->GetFrame().Tree().FirstChild(); child;
    child = child->Tree().NextSibling()) {
    if (!child->IsLocalFrame())
      continue;
    if (LocalFrameView* child_view = ToLocalFrame(child)->View()) {
      // Check to make sure we can get both the element and the LayoutObject
      // for this FrameView, if we can't just move on to the next object.
      // FIXME: Plugin occlusion by remote frames is probably broken.
      HTMLElement* element = child_view->GetFrame().DeprecatedLocalOwner();
      if (element && element->GetLayoutObject()) {
        LayoutObject* iframeRenderer = element->GetLayoutObject();

        if (IsA<HTMLIFrameElement>(*element) &&
          intersectsRect(iframeRenderer, frameRect)) {
          getObjectStack(iframeRenderer, &iframeZstack);
          if (iframeIsAbovePlugin(iframeZstack, pluginZstack))
            addToOcclusions(ToLayoutBox(iframeRenderer), occlusions);
        }
      }
    }
  }

  // Occlusions by top layer elements.
  // FIXME: There's no handling yet for the interaction between top layer and
  // iframes. For example, a plugin in the top layer will be occluded by an
  // iframe. And a plugin inside an iframe in the top layer won't be respected
  // as being in the top layer.
  const Element* ancestor = topLayerAncestor(element);
  Document* document = parentFrameView->GetFrame().GetDocument();
  const HeapVector<Member<Element>>& elements = document->TopLayerElements();
  size_t start = ancestor ? elements.Find(ancestor) + 1 : 0;
  for (size_t i = start; i < elements.size(); ++i)
    addTreeToOcclusions(elements[i]->GetLayoutObject(), frameRect, occlusions);
}

}  // namespace blink
