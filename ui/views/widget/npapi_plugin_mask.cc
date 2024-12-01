#include "ui/views/widget/npapi_plugin_mask.h"

namespace views {

NpapiPluginMask::NpapiPluginMask() = default;
NpapiPluginMask::~NpapiPluginMask()
{
    observers_.clear();
}

void NpapiPluginMask::SetShadowInsets(const gfx::Insets &shadow) {
  shadow_ = shadow;
}

void NpapiPluginMask::SetObservers(const std::vector<NpapiPluginMaskObserver *>& observers){
  observers_ = observers;
}

void NpapiPluginMask::MoveRect(const views::Widget* widget,
                                 const gfx::Rect &new_rect) {
    gfx::Rect rect(new_rect);
    rect.Inset(shadow_);
    for(NpapiPluginMaskObserver* observer: observers_)
      observer->MoveRect(widget, rect);
  }

  void NpapiPluginMask::ShowRect(const views::Widget* widget,
                                 const gfx::Rect &new_rect) {
    gfx::Rect rect(new_rect);
    rect.Inset(shadow_);
    for(NpapiPluginMaskObserver* observer: observers_)
      observer->ShowRect(widget, rect);
  }

  void NpapiPluginMask::HideRect(const views::Widget* widget,
                                 const gfx::Rect &new_rect) {
    gfx::Rect rect(new_rect);
    rect.Inset(shadow_);
    for(NpapiPluginMaskObserver* observer: observers_)
      observer->HideRect(widget, rect);
  }

  void NpapiPluginMask::AddObserver(NpapiPluginMaskObserver *observer) {
    auto iter = std::find(observers_.begin(), observers_.end(), observer);
    if(iter == observers_.end()) {
      observers_.push_back(observer);
    }
  }

  void NpapiPluginMask::DeleteObserver(NpapiPluginMaskObserver *observer) {
      auto iter = std::find(observers_.begin(), observers_.end(), observer);
      if(iter != observers_.end())
          observers_.erase(iter);
  }

  void NpapiPluginMask::AddWidgetObserver(Widget *widget) {
    for(NpapiPluginMaskObserver* observer: observers_)
      observer->AddWidgetObserver(widget);
  }

  void NpapiPluginMask::DeleteWidgetObserver(Widget *widget) {
      for(NpapiPluginMaskObserver* observer: observers_)
        observer->DeleteWidgetObserver(widget);
  }

}  // namespace views

