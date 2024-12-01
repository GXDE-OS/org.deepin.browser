// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_RENDERER_NPAPI_RENDERER_PLUGIN_RESOURCE_FETCHER_H
#define CONTENT_RENDERER_NPAPI_RENDERER_PLUGIN_RESOURCE_FETCHER_H

#include <string>
#include <vector>


#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/strings/string_piece.h"
#include "base/threading/thread_task_runner_handle.h"
#include "content/common/content_export.h"
// #include "content/common/possibly_associated_interface_ptr.h"
// #include "content/public/common/url_loader_throttle.h"
#include "third_party/blink/public/common/loader/url_loader_throttle.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/service_manager/public/cpp/connector.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/simple_watcher.h"




namespace content {

class RenderFrameImpl;

class CONTENT_EXPORT PluginResourceFetcher {
public:
  class Resource {
  public:
    Resource();

    int request_id;
    int resource_id;
    int response_code;
    std::string mime;
    std::string head;
    std::string data;
  };

  class Delegate {
  public:
    virtual void OnFetchResourceComplete(const Resource&) = 0;
  };

  PluginResourceFetcher(const GURL& url, Delegate* delegate);
  ~PluginResourceFetcher();

  void SetMethod(const std::string& method);
  void SetBody(const std::string& body);
  void SetHeader(const std::string& header, const std::string& value);
  void SetSiteCookies(const GURL& cookies);
  
  void StartAsync(int request_id, int resource_id, RenderFrameImpl* render_frame);
  void StartAsyncInsidePluginProcess(int request_id, int resource_id);

  void SetTimeout(const base::TimeDelta& timeout);

  void OnClientConnectionError(uint32_t e, const std::string& reason);

  void OnFetchResourceComplete(Resource&);
  
private:
  class ClientImpl;

  void OnLoadComplete();
  void OnTimeout();
  void OnReleaseResource();

  Delegate* delegate_;

  std::unique_ptr<ClientImpl> client_;
  // Request to send.
  network::ResourceRequest request_;
  // Limit how long to wait for the server.
  base::OneShotTimer timeout_timer_;
  base::OneShotTimer delay_task_;
  /////////////////////////////////////////////////////////////////////////////////////
  network::mojom::URLLoaderFactoryAssociatedPtr url_loader_factory_;
  std::unique_ptr<service_manager::Connector> connector_;

  Resource resource_;

  /////////////////////////////////////////////////////////////////////////////////////
  int request_id_;
  int resource_id_;

  GURL url_;

  DISALLOW_COPY_AND_ASSIGN(PluginResourceFetcher);
};

}  // namespace content

#endif  // CONTENT_RENDERER_NPAPI_RENDERER_PLUGIN_RESOURCE_FETCHER_H
