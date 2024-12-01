/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 * Copyright (C) 2004, 2006, 2008, 2009 Apple Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifndef Use_Uniontech_HTMLAppletElement
#define Use_Uniontech_HTMLAppletElement

#include "html_plugin_element.h"

namespace blink {

class KURL;

class HTMLAppletElement final : public HTMLPlugInElement {
    DEFINE_WRAPPERTYPEINFO();

public:
    HTMLAppletElement(Document&, const CreateElementFlags = CreateElementFlags());

    FrameOwnerElementType OwnerType() const final {
        return FrameOwnerElementType::kApplet;
    }

private:
    void ParseAttribute(const AttributeModificationParams&) override;
    bool IsURLAttribute(const Attribute&) const override;
    bool HasLegalLinkAttribute(const QualifiedName&) const override;

    bool LayoutObjectIsNeeded(const ComputedStyle&) const override;
    LayoutObject* CreateLayoutObject(const ComputedStyle&, LegacyLayout) override;

    LayoutEmbeddedContent* ExistingLayoutEmbeddedContent() const override;
    void UpdatePluginInternal() override;

    bool CanEmbedJava() const;
    bool CanEmbedURL(const KURL&) const;

    NamedItemType GetNamedItemType() const override { return NamedItemType::kNameOrId; }
};

} // namespace blink

#endif // Use_Uniontech_HTMLAppletElement
