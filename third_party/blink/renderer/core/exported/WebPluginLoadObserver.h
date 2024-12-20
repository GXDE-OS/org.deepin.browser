/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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

#ifndef WebPluginLoadObserver_h
#define WebPluginLoadObserver_h

#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"

namespace blink {

class WebPluginContainerImpl;
struct WebURLError;

class WebPluginLoadObserver {
public:
    WebPluginLoadObserver(WebPluginContainerImpl* pluginContainer,
                          const WebURL& notifyURL, void* notifyData)
        : m_pluginContainer(pluginContainer)
        , m_notifyURL(notifyURL)
        , m_notifyData(notifyData)
    {
    }

    ~WebPluginLoadObserver();

    const WebURL& url() const { return m_notifyURL; }

    void clearPluginContainer() { m_pluginContainer = 0; }
    void didFinishLoading();
    void didFailLoading(const WebURLError&);

private:
    WeakPersistent<WebPluginContainerImpl> m_pluginContainer;
    WebURL m_notifyURL;
    void* m_notifyData;
};

} // namespace blink

#endif
