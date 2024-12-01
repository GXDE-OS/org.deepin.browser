#ifndef UI_VIEWS_WIDGET_NPAPI_PLUGIN_MASK_H_
#define UI_VIEWS_WIDGET_NPAPI_PLUGIN_MASK_H_

#include <vector>

#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/insets.h"
#include "ui/views/views_export.h"

namespace views {
  class Widget;
  class NpapiPluginMaskObserver;

  // this class is only used for forwarding message
  // that contains invalidated rect
  // from pop-up dialog to npapi plugin
  class VIEWS_EXPORT NpapiPluginMask {
    public:
      NpapiPluginMask();
      virtual ~NpapiPluginMask();

      void MoveRect(const views::Widget* widget, const gfx::Rect& new_rect);
      void ShowRect(const views::Widget* widget, const gfx::Rect& new_rect);
      void HideRect(const views::Widget* widget, const gfx::Rect& new_rect);
      void SetShadowInsets(const gfx::Insets &shadow);

      void SetObservers(const std::vector<NpapiPluginMaskObserver *>& observers);
      
      void AddObserver(NpapiPluginMaskObserver *observer);
      void DeleteObserver(NpapiPluginMaskObserver *observer);


      void AddWidgetObserver(views::Widget* widget) ;
      void DeleteWidgetObserver(views::Widget* widget) ;

    protected:
      std::vector<NpapiPluginMaskObserver *> observers_;
      gfx::Insets shadow_;
  };

  class NpapiPluginMaskObserver {
  public:
    virtual ~NpapiPluginMaskObserver() {}
    virtual void MoveRect(const views::Widget*, const gfx::Rect& new_rect) = 0;
    virtual void ShowRect(const views::Widget*, const gfx::Rect& new_rect) = 0;
    virtual void HideRect(const views::Widget*, const gfx::Rect& new_rect) = 0;

    virtual void AddWidgetObserver(views::Widget* widget) = 0;
    virtual void DeleteWidgetObserver(views::Widget* widget) = 0;
  };

}  // namespace views

#endif  // UI_VIEWS_WIDGET_NPAPI_PLUGIN_MASK_H_
