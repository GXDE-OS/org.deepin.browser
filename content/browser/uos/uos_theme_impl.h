#ifndef CONTENT_BROWSER_RENDERER_HOST_UOS_UOS_THEME_IMPL_H_
#define CONTENT_BROWSER_RENDERER_HOST_UOS_UOS_THEME_IMPL_H_
#include "third_party/blink/public/mojom/uos/uos_theme.mojom.h"
// #include "content/common/renderer_host.mojom.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
namespace content {

class UosThemeImpl : public blink::mojom::UosTheme {
 public:
  // NOTE: A common pattern for interface implementations which have one
  // instance per client is to take an InterfaceRequest in the constructor.
 
  explicit UosThemeImpl();

  ~UosThemeImpl() override;

  static void Create(mojo::PendingReceiver<blink::mojom::UosTheme> receiver);

private:  
  
  void GetUosTheme(GetUosThemeCallback callback);
 
  SEQUENCE_CHECKER(sequence_checker_);

  DISALLOW_COPY_AND_ASSIGN(UosThemeImpl);   
	
};
}
#endif  // CONTENT_BROWSER_RENDERER_HOST_UOS_UOS_THEME_IMPL_H_