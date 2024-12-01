#include "content/browser/uos/uos_theme_impl.h"  
#include <utility>  
#include "base/bind.h"  
#include "uos/dbus_thread_manager.h"
#include "uos/dde/dde_appearance_theme_client.h"
#include "content/public/browser/browser_thread.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "uos/dde/dde_constants.h"

namespace content{  
    UosThemeImpl::UosThemeImpl() = default;

    UosThemeImpl::~UosThemeImpl() = default;

    // static
    void UosThemeImpl::Create(
        mojo::PendingReceiver<blink::mojom::UosTheme> receiver) {
        mojo::MakeSelfOwnedReceiver(std::make_unique<UosThemeImpl>(),
                                std::move(receiver));
    }

    void  UosThemeImpl::GetUosTheme(GetUosThemeCallback callback){    
       bool isDark = dbus::uos::DBusThreadManager::Get()->GetDdeAppearanceThemeClient()->isUseDarkColor();
       if(isDark){
            std::move(callback).Run("dark");
       }else{
            std::move(callback).Run("light");
       }
    }
} // namespace content  
