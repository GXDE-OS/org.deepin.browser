
#include <iostream>

#include "base/memory/ptr_util.h"
#include "base/message_loop/message_pump_type.h"
#include "base/threading/thread.h"

#include "newtabs_thread_manager.h"

namespace uos {
namespace customize_tab {

static CustomizeNewTabsThreadManager * g_customize_newtabs_thread_manager = nullptr;

CustomizeNewTabsThreadManager::CustomizeNewTabsThreadManager() {
    /*
    base::Thread::Options thread_options;
    thread_options.message_pump_type = base::MessagePumpType::IO;
    customize_newtabs_thread_.reset(new base::Thread("Customize Newtabs thread"));
    customize_newtabs_thread_->StartWithOptions(thread_options); */

    core_.reset(new CustomizeNewTabsCore());
}

CustomizeNewTabsThreadManager::~CustomizeNewTabsThreadManager() {
    /*
    if (customize_newtabs_thread_) {
        customize_newtabs_thread_->Stop();
    } */
}

CustomizeNewTabsThreadManager * CustomizeNewTabsThreadManager::Get() {
    return g_customize_newtabs_thread_manager;
}


void CustomizeNewTabsThreadManager::Initialize() {
    if (!g_customize_newtabs_thread_manager) {
        g_customize_newtabs_thread_manager = new CustomizeNewTabsThreadManager();
    }

}

bool CustomizeNewTabsThreadManager::IsInitialized() {
    return !!g_customize_newtabs_thread_manager;
}

void CustomizeNewTabsThreadManager::Shutdown() {
    if (g_customize_newtabs_thread_manager) {
        delete g_customize_newtabs_thread_manager;
    }
    g_customize_newtabs_thread_manager = nullptr;
}

CustomizeNewTabsCore * CustomizeNewTabsThreadManager::getCore() {
    return core_.get();
}

}
}