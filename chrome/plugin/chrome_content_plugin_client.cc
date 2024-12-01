// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/plugin/chrome_content_plugin_client.h"

#ifdef V8_USE_EXTERNAL_STARTUP_DATA
#include "gin/v8_initializer.h"
#endif

#include "base/command_line.h"
#include "base/feature_list.h"
#include "build/build_config.h"
#include "chrome/common/chrome_switches.h"
#include "components/version_info/version_info.h"
#include "content/public/common/user_agent.h"
#include "content/public/common/content_switches.h"
#include "net/http/http_util.h"
#include "third_party/blink/public/common/features.h"
#include "ui/base/ui_base_switches.h"

void ChromeContentPluginClient::PreSandboxInitialization() {
#ifdef V8_USE_EXTERNAL_STARTUP_DATA
  gin::V8Initializer::LoadV8Snapshot();
  LOG(WARNING) << "ChromeContentPluginClient::PreSandboxInitialization NEED CHECK";
  //gin::V8Initializer::LoadV8Natives();
#endif
}

std::string ChromeContentPluginClient::GetUserAgentInPlugin() {
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
  if (command_line->HasSwitch(switches::kUserAgent)) {
    std::string ua = command_line->GetSwitchValueASCII(switches::kUserAgent);
    if (net::HttpUtil::IsValidHeaderValue(ua))
      return ua;
    LOG(WARNING) << "Ignored invalid value for flag --" << switches::kUserAgent;
  }

  if (base::FeatureList::IsEnabled(blink::features::kFreezeUserAgent)) {
    return content::GetFrozenUserAgent(
        command_line->HasSwitch(switches::kUseMobileUserAgent),
        version_info::GetMajorVersionNumber());
  }

  std::string product = version_info::GetProductNameAndVersionForUserAgent();
#if defined(OS_ANDROID)
  if (command_line->HasSwitch(switches::kUseMobileUserAgent))
    product += " Mobile";
#endif
  return content::BuildUserAgentFromProduct(product);
}
