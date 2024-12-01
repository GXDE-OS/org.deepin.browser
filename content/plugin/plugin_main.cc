// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "build/build_config.h"

#if defined(OS_WIN)
#include <windows.h>
#endif

#include "base/base_paths.h"
#include "base/command_line.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_executor.h"
#include "base/threading/platform_thread.h"
#include "build/build_config.h"
#include "content/child/child_process.h"
#include "content/common/content_constants_internal.h"
#include "content/common/content_switches_internal.h"
#include "content/plugin/plugin_thread.h"
#include "content/public/common/content_client.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/main_function_params.h"

namespace content {

#if defined(OS_MACOSX)
// Initializes the global Cocoa application object.
void InitializeChromeApplication();
#elif defined(OS_LINUX)
#if defined(ARCH_CPU_X86_64)
// Work around an unimplemented instruction in 64-bit Flash.	
void WorkaroundFlashLAHF();
#endif
#endif

// main() routine for running as the plugin process.
int PluginMain(const MainFunctionParams& parameters) {
  // The main thread of the plugin services UI.
#if defined(OS_MACOSX)
  InitializeChromeApplication();
#endif

  const base::CommandLine& parsed_command_line = parameters.command_line;
  if (parsed_command_line.HasSwitch(switches::kPluginStartupDialog)) {
    WaitForDebugger("NPAPI Plugin Process ====>");
  }

  base::SingleThreadTaskExecutor main_thread_task_executor(base::MessagePumpType::UI);
  base::PlatformThread::SetName("CrPluginMain");
  base::trace_event::TraceLog::GetInstance()->set_process_name("Plugin Process");
  base::trace_event::TraceLog::GetInstance()->SetProcessSortIndex(kTraceEventPluginProcessSortIndex);

#if defined(OS_LINUX)
#if defined(ARCH_CPU_X86_64)
  WorkaroundFlashLAHF();
#endif
#endif

  {
    ChildProcess plugin_process;
    base::RunLoop run_loop;
    plugin_process.set_main_thread(new PluginThread(run_loop.QuitClosure()));
    run_loop.Run();
  }

  return 0;
}

}  // namespace content