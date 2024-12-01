#ifndef _NEWTABS_THREAD_MANAGER_
#define _NEWTABS_THREAD_MANAGER_

#include <memory>

#include "customize_newtabs_core.h"

namespace base {
class Thread;
}

namespace uos {
namespace customize_tab {


class CustomizeNewTabsThreadManager {
public:
    
    static bool IsInitialized();
    static void Shutdown();

    static CustomizeNewTabsThreadManager * Get();

    CustomizeNewTabsCore * getCore();
    static void Initialize();

private:
    explicit CustomizeNewTabsThreadManager();
    ~CustomizeNewTabsThreadManager();

private:
    std::unique_ptr<base::Thread> customize_newtabs_thread_;
    std::unique_ptr<CustomizeNewTabsCore> core_;


};
}
}


#endif