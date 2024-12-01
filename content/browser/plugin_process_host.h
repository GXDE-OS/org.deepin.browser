// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_PLUGIN_PROCESS_HOST_H_
#define CONTENT_BROWSER_PLUGIN_PROCESS_HOST_H_

#include "build/build_config.h"

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/process/process_handle.h"
#include "content/browser/loader/resource_message_filter.h"
#include "content/common/content_export.h"
#include "content/public/browser/browser_child_process_host_delegate.h"
#include "content/public/browser/browser_child_process_host_iterator.h"
#include "content/public/common/process_type.h"
#include "content/public/common/resource_type.h"
#include "content/public/common/webplugininfo.h"
#include "ipc/ipc_channel_proxy.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/cors/origin_access_list.h"
#include "services/network/resource_scheduler/resource_scheduler.h"
#include "services/network/public/mojom/network_context.mojom.h"
#include "services/network/network_service.h"
#include "services/network/network_context.h"
#include "services/network/public/cpp/simple_url_loader.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/cpp/simple_url_loader_stream_consumer.h"
#include "ui/gfx/native_widget_types.h"

struct ResourceHostMsg_Request;
struct PluginProcessMsg_CreateLoaderAndStart_Params;

namespace gfx {
class Rect;
}

namespace IPC {
struct ChannelHandle;
}

namespace net {
class URLRequestContext;
}

namespace content {
class BrowserChildProcessHostImpl;
class ResourceContext;
class BrowserContext;
class ResourceRequesterInfo;
class PluginResourceLoaderClient;
class PluginResourceLoaderDelegate;

class PluginResourceLoader : public network::SimpleURLLoaderStreamConsumer {
 public:
  class Resource {
   public:
    Resource();

    int request_id;
    int resource_id;
    int routing_id;
    int response_code;
    std::string mime;
    std::string head;
    std::string data;
  };

  PluginResourceLoader(std::unique_ptr<network::ResourceRequest> resource_request,
                       network::mojom::URLLoaderFactory* url_loader_factory,
                       int request_id,
                       int resource_id,
                       int routing_id,
                       PluginResourceLoaderDelegate* delegate);

  PluginResourceLoader(scoped_refptr<ResourceRequesterInfo> requester_info,
	                     int request_id,
                       int resource_id,
                       int routing_id,
                       const network::ResourceRequest& request,
	                     scoped_refptr<base::SingleThreadTaskRunner> runner,
                       PluginResourceLoaderDelegate* delegate,
                       network::mojom::NetworkContext* network_context,
                       BrowserContext* browser_context);
  ~PluginResourceLoader() override;

  void SetTimeout(const base::TimeDelta& timeout);

  void CancelRequest();

  void OnDataReceived(base::StringPiece string_piece, base::OnceClosure resume) override;

  void OnComplete(bool success) override;

  void OnRetry(base::OnceClosure start_retry) override;

 private:
  friend class PluginResourceLoaderClient;
  void OnFetchResourceComplete(Resource&);

  void OnLoadComplete();
  void OnTimeout();
  void OnReleaseResource();

  PluginResourceLoaderDelegate* delegate_;

  std::unique_ptr<PluginResourceLoaderClient> client_;
  // Request to send.
  network::ResourceRequest request_;
  // Limit how long to wait for the server.
  base::OneShotTimer timeout_timer_;
  base::OneShotTimer delay_task_;

  network::mojom::URLLoaderFactoryAssociatedPtr url_loader_factory_;
  Resource resource_;
  int request_id_;
  int resource_id_;
  int routing_id_;

  GURL url_;

  BrowserContext* browser_context_;
  network::cors::OriginAccessList origin_access_list_;
  mojo::Remote<network::mojom::URLLoaderFactory> cors_url_loader_factory_remote_;
  std::unique_ptr<net::URLRequestContext> url_request_context_;
  network::ResourceScheduler resource_scheduler_;
  mojo::Remote<network::mojom::NetworkService> network_service_remote;
  std::unique_ptr<network::NetworkService> network_service_;
  std::unique_ptr<network::NetworkContext> network_context_;
  mojo::Remote<network::mojom::NetworkContext> network_context_remote_;

  std::unique_ptr<network::SimpleURLLoader> simple_url_loader_;

  std::string data_;
  std::string head_;
  std::string mime_;

  DISALLOW_COPY_AND_ASSIGN(PluginResourceLoader);
};

class PluginResourceLoaderDelegate {
 public:
  virtual void OnFetchResourceComplete(const PluginResourceLoader::Resource&) = 0;
};

// Represents the browser side of the browser <--> plugin communication
// channel.  Different plugins run in their own process, but multiple instances
// of the same plugin run in the same process.  There will be one
// PluginProcessHost per plugin process, matched with a corresponding
// PluginProcess running in the plugin process.  The browser is responsible for
// starting the plugin process when a plugin is created that doesn't already
// have a process.  After that, most of the communication is directly between
// the renderer and plugin processes.
class CONTENT_EXPORT PluginProcessHost : public BrowserChildProcessHostDelegate,
                                         public PluginResourceLoaderDelegate,
                                         public IPC::Sender {
 public:
  class Client {
   public:
    // Returns an opaque unique identifier for the process requesting
    // the channel.
    virtual int ID() = 0;
    // Returns the resource context for the renderer requesting the channel.
    virtual ResourceContext* GetResourceContext() = 0;
    virtual bool OffTheRecord() = 0;
    virtual void SetPluginInfo(const WebPluginInfo& info) = 0;
    virtual void OnFoundPluginProcessHost(PluginProcessHost* host) = 0;
    virtual void OnSentPluginChannelRequest() = 0;
    // The client should delete itself when one of these methods is called.
    virtual void OnChannelOpened(const IPC::ChannelHandle& handle) = 0;
    virtual void OnError() = 0;
    virtual BrowserContext* GetBrowserContext() = 0;

   protected:
    virtual ~Client() {}
  };

  PluginProcessHost();
  ~PluginProcessHost() override;

  // IPC::Sender implementation:
  bool Send(IPC::Message* message) override;

  // Initialize the new plugin process, returning true on success. This must
  // be called before the object can be used.
  bool Init(const WebPluginInfo& info);

  // Force the plugin process to shutdown (cleanly).
  void ForceShutdown();

  bool OnMessageReceived(const IPC::Message& msg) override;
  void OnChannelConnected(int32_t peer_pid) override;
  void OnChannelError() override;

  // Tells the plugin process to create a new channel for communication with a
  // renderer.  When the plugin process responds with the channel name,
  // OnChannelOpened in the client is called.
  void OpenChannelToPlugin(Client* client);

  // This function is called to cancel pending requests to open new channels.
  void CancelPendingRequest(Client* client);

  // This function is called to cancel sent requests to open new channels.
  void CancelSentRequest(Client* client);

  // This function is called on the IO thread once we receive a reply from the
  // modal HTML dialog (in the form of a JSON string). This function forwards
  // that reply back to the plugin that requested the dialog.
  void OnModalDialogResponse(const std::string& json_retval,
                             IPC::Message* sync_result);

  const WebPluginInfo& info() const { return info_; }

  // Given a pid of a plugin process, returns the plugin information in |info|
  // if we know about that process. Otherwise returns false.
  // This method can be called on any thread.
  static bool GetWebPluginInfoFromPluginPid(base::ProcessId pid,
                                            WebPluginInfo* info);

  void OnFetchResourceComplete(const PluginResourceLoader::Resource&) override;

 private:
  // Sends a message to the plugin process to request creation of a new channel
  // for the given mime type.
  void RequestPluginChannel(Client* client);

  // Message handlers.
  void OnChannelCreated(const IPC::ChannelHandle& channel_handle);
  void OnChannelDestroyed(int renderer_id);

  void OnCreateLoaderAndStart(const PluginProcessMsg_CreateLoaderAndStart_Params& params);
  void PrepareToCreateLoaderAndStartOnUI(int plugin_process_id, int request_id);
  void CreateLoaderAndStartOnIO(int request_id,
                                std::unique_ptr<network::PendingSharedURLLoaderFactory> pending_shared_url_loader_factory);

  void OnProcessCrashed(int exit_code) override;

  void CancelRequests();

  // These are channel requests that we are waiting to send to the
  // plugin process once the channel is opened.
  std::vector<Client*> pending_requests_;

  // These are the channel requests that we have already sent to
  // the plugin process, but haven't heard back about yet.
  std::list<Client*> sent_requests_;

  // Information about the plugin.
  WebPluginInfo info_;

  // The pid of the plugin process.
  int pid_;

  // Map from render_process_id to its ResourceContext. Instead of storing the
  // raw pointer, we store the struct below. This is needed because a renderer
  // process can actually have multiple IPC channels to the same plugin process,
  // depending on timing conditions with plugin instance creation and shutdown.
  struct ResourceContextEntry {
    ResourceContext* resource_context;
    int ref_count;
  };
  typedef std::map<int, ResourceContextEntry> ResourceContextMap;
  ResourceContextMap resource_context_map_;

  // A random token used to identify the child process to Mojo.
  const std::string mojo_child_token_;

  std::unique_ptr<BrowserChildProcessHostImpl> process_;

  BrowserContext* browser_context_;

  scoped_refptr<network::SharedURLLoaderFactory> shared_url_loader_factory_;

  typedef std::map<int, std::unique_ptr<PluginProcessMsg_CreateLoaderAndStart_Params>> PluginProcessMsg_CreateLoaderAndStart_ParamsMap;
  PluginProcessMsg_CreateLoaderAndStart_ParamsMap params_map_;

  typedef std::map<int, std::unique_ptr<PluginResourceLoader>> PluginResourceLoaderMap;
  PluginResourceLoaderMap plugin_resource_loader_map_;

  DISALLOW_COPY_AND_ASSIGN(PluginProcessHost);
};

class PluginProcessHostIterator
    : public BrowserChildProcessHostTypeIterator<PluginProcessHost> {
 public:
  PluginProcessHostIterator()
      : BrowserChildProcessHostTypeIterator<PluginProcessHost>(
          PROCESS_TYPE_PLUGIN) {}
};

}  // namespace content

#endif  // CONTENT_BROWSER_PLUGIN_PROCESS_HOST_H_
