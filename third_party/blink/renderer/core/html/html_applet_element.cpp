/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2000 Stefan Schimanski (1Stein@gmx.de)
 * Copyright (C) 2004, 2005, 2006, 2008, 2009, 2012 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
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
 */

#include "third_party/blink/renderer/core/html/html_applet_element.h"

#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#if USE_UNIONTECH_NPAPI  // HEADERS
#include "third_party/blink/renderer/core/frame/settings.h"
#else
#include "third_party/blink/renderer/core/frame/Settings.h"
#endif
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/html/html_param_element.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_object.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#if USE_UNIONTECH_NPAPI  // HEADERS
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#else
#include "third_party/blink/renderer/platform/weborigin/KURL.h"
#endif
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

#if defined(USE_UNIONTECH_NPAPI)
#include "third_party/blink/renderer/core/layout/LayoutApplet.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/public/common/frame/sandbox_flags.h"
#endif

namespace blink {

using namespace html_names;

HTMLAppletElement::HTMLAppletElement(Document& document,
                                     const CreateElementFlags flags)
    : HTMLPlugInElement(html_names::kAppletTag,
                        document,
                        flags,
                        kShouldNotPreferPlugInsForImages)
{
    service_type_ = "application/x-java-applet";
}

void HTMLAppletElement::ParseAttribute(
    const AttributeModificationParams& params)
{
#if defined(USE_UNIONTECH_NPAPI)
    if (params.name == kAltAttr
        || params.name == kArchiveAttr
        || params.name == kCodeAttr
        || params.name == kCodebaseAttr
        || params.name == kMayscriptAttr
        || params.name == kObjectAttr) {
        // Do nothing.
        return;
    }
#endif
    LOG(INFO) << "[NPAPI] HTMLAppletElement::ParseAttribute";
    HTMLPlugInElement::ParseAttribute(params);
}

bool HTMLAppletElement::IsURLAttribute(const Attribute& attribute) const
{
#if defined(USE_UNIONTECH_NPAPI)
    return attribute.GetName() == kCodebaseAttr || attribute.GetName() == kObjectAttr
        || HTMLPlugInElement::IsURLAttribute(attribute);
#else
    LOG(INFO) << "[NPAPI] HTMLAppletElement::IsURLAttribute";
    return false;
#endif
}

bool HTMLAppletElement::HasLegalLinkAttribute(const QualifiedName& name) const
{
#if defined(USE_UNIONTECH_NPAPI)
    return name == kCodebaseAttr || HTMLPlugInElement::HasLegalLinkAttribute(name);
#else
    LOG(INFO) << "[NPAPI] HTMLAppletElement::HasLegalLinkAttribute";
    return false;
#endif
}

bool HTMLAppletElement::LayoutObjectIsNeeded(const ComputedStyle& style) const
{
#if defined(USE_UNIONTECH_NPAPI)
    if (!FastHasAttribute(kCodeAttr))
        return false;
    return HTMLPlugInElement::LayoutObjectIsNeeded(style);
#else
    LOG(INFO) << "[NPAPI] HTMLAppletElement::LayoutObjectIsNeeded";
    return false;
#endif
}

LayoutObject* HTMLAppletElement::CreateLayoutObject(const ComputedStyle& style, LegacyLayout legacy)
{
#if defined(USE_UNIONTECH_NPAPI)
    if (!CanEmbedJava())
        return LayoutObject::CreateObject(this, style, legacy);

    if (usePlaceholderContent())
        return new LayoutBlockFlow(this);

    return new LayoutApplet(this);
#else
    LOG(INFO) << "[NPAPI] HTMLAppletElement::CreateLayoutObject";
    return nullptr;
#endif
}

LayoutEmbeddedContent* HTMLAppletElement::ExistingLayoutEmbeddedContent() const
{
    return GetLayoutEmbeddedContent();
}

void HTMLAppletElement::UpdatePluginInternal()
{
    LOG(INFO) << "[NPAPI] HTMLAppletElement::UpdatePluginInternal";
#if defined(USE_UNIONTECH_NPAPI)
    SetNeedsPluginUpdate(false);
    // FIXME: This should ASSERT isFinishedParsingChildren() instead.
    if (!IsFinishedParsingChildren()){
        LOG(ERROR) << "[NPAPI] HTMLAppletElement::IsFinishedParsingChildren";
        return;
    }

    LayoutEmbeddedObject* layoutObject = layoutEmbeddedObject();

    LocalFrame* frame = GetDocument().GetFrame();
    DCHECK(frame);

    Vector<String> paramNames;
    Vector<String> paramValues;

    const AtomicString& codeBase = getAttribute(kCodebaseAttr);
    if (!codeBase.IsNull()) {
        KURL codeBaseURL = GetDocument().CompleteURL(codeBase);
        paramNames.push_back("codeBase");
        paramValues.push_back(codeBase.GetString());
    }

    const AtomicString& archive = getAttribute(kArchiveAttr);
    if (!archive.IsNull()) {
        paramNames.push_back("archive");
        paramValues.push_back(archive.GetString());
    }

    const AtomicString& code = getAttribute(kCodeAttr);
    paramNames.push_back("code");
    paramValues.push_back(code.GetString());

    // If the 'codebase' attribute is set, it serves as a relative root for the file that the Java
    // plugin will load. If the 'code' attribute is set, and the 'archive' is not set, then we need
    // to check the url generated by resolving 'code' against 'codebase'. If the 'archive'
    // attribute is set, then 'code' points to a class inside the archive, so we need to check the
    // url generated by resolving 'archive' against 'codebase'.
    KURL urlToCheck;
    KURL rootURL;
    if (!codeBase.IsNull())
        rootURL = GetDocument().CompleteURL(codeBase);
    if (rootURL.IsNull() || !rootURL.IsValid())
        rootURL = GetDocument().Url();

    if (!archive.IsNull())
        urlToCheck = KURL(rootURL, archive);
    else if (!code.IsNull())
        urlToCheck = KURL(rootURL, code);
    if (!CanEmbedURL(urlToCheck))
        return;

    const AtomicString& name = GetDocument().IsHTMLDocument() ? GetNameAttribute() : GetIdAttribute();
    if (!name.IsNull()) {
        paramNames.push_back("name");
        paramValues.push_back(name.GetString());
    }

    paramNames.push_back("baseURL");
    KURL baseURL = GetDocument().BaseURL();
    paramValues.push_back(baseURL.GetString());

    const AtomicString& mayScript = getAttribute(kMayscriptAttr);
    if (!mayScript.IsNull()) {
        paramNames.push_back("mayScript");
        paramValues.push_back(mayScript.GetString());
    }

    for (HTMLParamElement* param = Traversal<HTMLParamElement>::FirstChild(*this); param; param = Traversal<HTMLParamElement>::NextSibling(*param)) {
        if (param->GetName().IsEmpty())
            continue;

        paramNames.push_back(param->GetName());
        paramValues.push_back(param->Value());
    }

    WebPluginContainerImpl* plugin = nullptr;
    if (frame->Loader().AllowPlugins(kAboutToInstantiatePlugin))
        plugin = frame->Client()->CreateJavaAppletWidget(this, baseURL, paramNames, paramValues);

    if (!plugin) {
        if (!layoutObject->ShowsUnavailablePluginIndicator())
            layoutObject->SetPluginAvailability(LayoutEmbeddedObject::kPluginMissing);
        return;
    }
    GetDocument().SetContainsPlugins();
    SetEmbeddedContentView(reinterpret_cast<blink::EmbeddedContentView*>(plugin));
    layoutObject->GetFrameView()->AddPlugin(plugin);
#endif
}

bool HTMLAppletElement::CanEmbedJava() const
{
    LOG(INFO) << "[NPAPI][TODO] HTMLAppletElement::CanEmbedJava";
#if defined(USE_UNIONTECH_NPAPI)
    if (GetDocument().IsSandboxed(blink::mojom::WebSandboxFlags::kPlugins))
        return false;

    Settings* settings = GetDocument().GetSettings();
    if (!settings)
        return false;
	
    // if (!settings->GetJavaEnabled())
    //     return false;
#endif
    return true;
}

bool HTMLAppletElement::CanEmbedURL(const KURL& url) const
{
    LOG(INFO) << "[NPAPI][TODO] HTMLAppletElement::CanEmbedURL";
#if defined(USE_UNIONTECH_NPAPI)
    if (!GetDocument().GetSecurityOrigin()->CanDisplay(url)) {
        GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kSecurity, mojom::ConsoleMessageLevel::kError,
            "Not allowed to load local resource: " + url.GetString()));
        LOG(INFO) << "[NPAPI][TODO] HTMLAppletElement::CanDisplay";
        return false;
    }

    if (!GetDocument().GetContentSecurityPolicy()->AllowObjectFromSource(url)
        || !GetDocument().GetContentSecurityPolicy()->AllowPluginTypeForDocument(GetDocument(), service_type_, service_type_, url)) {
        layoutEmbeddedObject()->SetPluginAvailability(LayoutEmbeddedObject::kPluginBlockedByContentSecurityPolicy);
        return false;
    }
    return true;
#else
    return false;
#endif
}

}
