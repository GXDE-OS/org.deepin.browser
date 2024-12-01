// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PLUGIN_PLUGIN_THREAD_H_
#define CONTENT_PLUGIN_PLUGIN_THREAD_H_

#include <stdint.h>

#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/native_library.h"
#include "build/build_config.h"
#include "content/child/child_thread_impl.h"
#include "content/child/npapi/plugin_lib.h"
#include "content/plugin/plugin_channel.h"

#if defined(OS_POSIX)
#include "base/file_descriptor_posix.h"
#endif

struct PluginProcessMsg_ResourceFetched_Params;

namespace content {
class BlinkPlatformImpl;

class PluginResourceDispatcherDelegate {
public:
  virtual void OnResourceFetched(int resource_id,
    int response_code, const std::string& mime,
    const std::string& head, const std::string& data) = 0;
};

// The PluginThread class represents a background thread where plugin instances
// live.  Communication occurs between WebPluginDelegateProxy in the renderer
// process and WebPluginDelegateStub in this thread through IPC messages.
class PluginThread : public ChildThreadImpl {
  public:
    PluginThread(base::RepeatingClosure quit_closure);
    ~PluginThread() override;
    void Shutdown() override;

    // Returns the one plugin thread.
    static PluginThread* current();

    // Tells the plugin thread to terminate the process forcefully instead of
    // exiting cleanly.
    void SetForcefullyTerminatePluginProcess();

    void AddPluginResourceDispatcherDelegate(int routing_id, PluginResourceDispatcherDelegate* delegate) {
      if (routing_id > 0 && delegate)
        plugin_resource_dispatcher_delegate_map_[routing_id] = delegate;
    }

    void RemovePluginResourceDispatcherDelegate(PluginResourceDispatcherDelegate* delegate) {
      if (!delegate)
        return;

      std::set<int> need_remove;
      for (auto index : plugin_resource_dispatcher_delegate_map_) {
        if (index.second == delegate)
          need_remove.insert(index.first);
      }
      for (auto index : need_remove) {
        plugin_resource_dispatcher_delegate_map_.erase(index);
      }
    }

  private:
    bool OnControlMessageReceived(const IPC::Message& msg) override;

    // Callback for when a channel has been created.
    void OnCreateChannel(int renderer_id, bool incognito);
    void OnPluginMessage(const std::vector<uint8_t>& data);
    void OnNotifyRenderersOfPendingShutdown();

    void OnResourceFetched(const PluginProcessMsg_ResourceFetched_Params& params);

#if defined(OS_MACOSX)
    void OnAppActivated();
    void OnPluginFocusNotify(uint32_t instance_id);
#endif

  typedef std::map<int, PluginResourceDispatcherDelegate*> PluginResourceDispatcherDelegateMap;
  typedef std::map<int, PluginResourceDispatcherDelegate*>::iterator PluginResourceDispatcherDelegateMapIterator;
  PluginResourceDispatcherDelegateMap plugin_resource_dispatcher_delegate_map_;

  // The plugin module which is preloaded in Init
  base::NativeLibrary preloaded_plugin_module_;

  bool forcefully_terminate_plugin_process_;

  std::unique_ptr<BlinkPlatformImpl> blink_platform_impl_;
  DISALLOW_COPY_AND_ASSIGN(PluginThread);
};

}  // namespace content

#endif  // CONTENT_PLUGIN_PLUGIN_THREAD_H_