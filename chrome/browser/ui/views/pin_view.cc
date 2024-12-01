// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef OPENSSL_NO_GMTLS
#include "chrome/browser/ui/views/pin_view.h"

#include <stddef.h>

#include "base/bind_helpers.h"
#include "build/build_config.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/profiles/profile_manager.h"
#include "chrome/browser/profiles/profile_window.h"
#include "chrome/browser/task_manager/task_manager_interface.h"
#include "chrome/browser/task_manager/task_manager_observer.h"
#include "chrome/browser/ui/browser_dialogs.h"
#include "chrome/browser/ui/browser_finder.h"
#include "chrome/browser/ui/browser_navigator_params.h"
#include "chrome/browser/ui/tabs/tab_strip_model.h"
#include "chrome/browser/ui/task_manager/task_manager_columns.h"
#include "chrome/browser/ui/views/chrome_layout_provider.h"
#include "chrome/common/pref_names.h"
#include "chrome/common/url_constants.h"
#include "chrome/grit/chromium_strings.h"
#include "chrome/grit/generated_resources.h"
#include "components/prefs/pref_service.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/models/table_model_observer.h"
#include "ui/views/border.h"
#include "ui/views/controls/label.h"
#include "ui/views/controls/scroll_view.h"
#include "ui/views/controls/table/table_view.h"
#include "ui/views/layout/fill_layout.h"
#include "ui/views/view.h"
#include "ui/views/widget/widget.h"
#include "ui/views/controls/button/label_button.h"
#include "ui/views/controls/button/md_text_button.h"

#include "chrome/browser/ui/views/textfield_layout.h"
#include "ui/views/controls/textfield/textfield.h"

#include "chrome/browser/ui/views/frame/browser_view.h"

#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "third_party/boringssl/src/crypto/skf/skf_manager.h"

#include "base/values.h"

#include "components/web_modal/single_web_contents_dialog_manager.h"
#include "components/web_modal/web_contents_modal_dialog_manager.h"
#include "components/web_modal/web_contents_modal_dialog_host.h"
#include "components/constrained_window/native_web_contents_modal_dialog_manager_views.h"

#include "ui/base/resource/resource_bundle.h"
#include "chrome/grit/theme_resources.h"

#if defined(OS_CHROMEOS)
#include "ash/public/cpp/shelf_item.h"
#include "ash/public/cpp/window_properties.h"
#include "chrome/grit/theme_resources.h"
#include "ui/aura/window.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/gfx/image/image_skia.h"
#endif  // defined(OS_CHROMEOS)

#if defined(OS_WIN)
#include "chrome/browser/shell_integration_win.h"
#include "ui/base/win/shell.h"
#include "ui/views/win/hwnd_util.h"

#endif  // defined(OS_WIN)

namespace task_manager1 {

PinView::~PinView() {
  // Delete child views now, while our table model still exists.
  RemoveAllChildViews(true);
}

// static
base::OnceClosure PinView::Show(net::SSLCertRequestInfo* certrequestinfo,content::WebContents* web_contents,
          std::unique_ptr<content::ClientCertificateDelegate> delegate,
      skfmodule * in_skf_module,
      X509_NAME * in_issuer) {
  
  // g_pin_view->host_port_name_=certrequestinfo->host_and_port.ToString();

  // On Chrome OS, pressing Search-Esc when there are no open browser windows
  // will open the task manager on the root window for new windows.
  // content::WebContents* responsible_web_contents = web_contents->GetResponsibleWebContents();
  // Browser* browser = chrome::FindBrowserWithWebContents(responsible_web_contents);
  // gfx::NativeWindow context =
  //      browser ? browser->window()->GetNativeWindow() : nullptr;
  // DialogDelegate::CreateDialogWidget(g_pin_view, nullptr, context);
  // g_pin_view->GetWidget()->SetZOrderLevel(ui::ZOrderLevel::kSecuritySurface);
  // g_pin_view->GetWidget()->Show();

  content::WebContents* responsible_web_contents = web_contents->GetResponsibleWebContents();
  LOG(ERROR)<<"responsible_web_contents->GetLoadState():"<<responsible_web_contents->GetLoadState().state;
  web_modal::WebContentsModalDialogManager* manager =
      web_modal::WebContentsModalDialogManager::FromWebContents(responsible_web_contents);
  DCHECK(manager);
  
  if(manager->IsDialogActive()){
    manager->CloseAllDialogs();
  }

  task_manager1::PinView* g_pin_view = new PinView();
  views::Widget* widget = DialogDelegate::CreateDialogWidget(g_pin_view, nullptr,
                  manager->delegate()->GetWebContentsModalDialogHost()->GetHostView());
  gfx::NativeWindow dialog = widget->GetNativeWindow();

  std::unique_ptr<web_modal::SingleWebContentsDialogManager> dialog_manager(
                  new constrained_window::NativeWebContentsModalDialogManagerViews(
                  dialog, manager));
  manager->ShowDialogWithManager(dialog, std::move(dialog_manager));
  
  // LOG(ERROR)<<"will set delegate.";
  g_pin_view->SetDelegate(std::move(delegate));
  g_pin_view->SetSkfModule(in_skf_module);
  g_pin_view->SetIssuer(in_issuer);
  return g_pin_view->GetCancellationCallback();
}

gfx::Size PinView::CalculatePreferredSize() const {
  return gfx::Size(200, 110);
}

gfx::Size PinView::GetMinimumSize() const {
  return gfx::Size(200, 110);
}

gfx::Size PinView::GetMaximumSize() const {
  return gfx::Size(200, 110);
}

views::View* PinView::GetInitiallyFocusedView() {
  return name_field_;
}

bool PinView::CanResize() const {
  return false;
}

bool PinView::CanMaximize() const {
  return false;
}

bool PinView::CanMinimize() const {
  return false;
}

gfx::ImageSkia PinView::GetWindowIcon() {
#if defined(OS_CHROMEOS)
  return *ui::ResourceBundle::GetSharedInstance().GetImageSkiaNamed(
      IDR_ASH_SHELF_ICON_TASK_MANAGER);
#else
  // return views::DialogDelegateView::GetWindowIcon();
  // return *(ui::ResourceBundle::GetSharedInstance().GetImageSkiaNamed(IDR_BOOKMARK_INFO));
  return *(ui::ResourceBundle::GetSharedInstance().GetImageSkiaNamed(IDR_PERMISSION_PROMPT_BUBBLE_VIEW_ICON));
#endif
}

bool PinView::ShouldShowWindowIcon() const{
  return true;
}

std::string PinView::GetWindowName() const {
  LOG(INFO)<<"----prefs::kTaskManagerWindowPlacement----"<<prefs::kTaskManagerWindowPlacement;
  return prefs::kTaskManagerWindowPlacement;
}

class SKFPrivateKey : public net::SSLPrivateKey {
 public:
  SKFPrivateKey(const std::string& provider_name) : 
                provider_name_(provider_name){}

  // net::SSLPrivateKey:
  std::string GetProviderName() override { return provider_name_; }
  std::vector<uint16_t> GetAlgorithmPreferences() override {
    return algorithm_preferences_;
  }
  void SetSkfModule(skfmodule * skf_module){
    skf_module_=skf_module;
  }

  void Sign(uint16_t algorithm,
            base::span<const uint8_t> input,
            net::SSLPrivateKey::SignCallback callback) override {
    std::vector<uint8_t> input_vector(input.begin(), input.end());
    std::vector<uint8_t> out;
    out.resize(256);
    size_t out_len;
    if(!skf_module_){
      return;
    }
    if(0 != skf_module_->skf_privatekey_sign(out.data(), &out_len, 256, NID_sm2, input.data(), input.size())){
      std::move(callback).Run(net::ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED,
                            /*signature=*/{});
      return;
    }
    out.resize(out_len);
    std::move(callback).Run(net::OK, out);
  }

 private:
  ~SKFPrivateKey() override = default;
  void Callback(net::SSLPrivateKey::SignCallback callback,
                int32_t net_error,
                const std::vector<uint8_t>& input) {
    DCHECK_LE(net_error, 0);
    DCHECK_NE(net_error, net::ERR_IO_PENDING);
    std::move(callback).Run(static_cast<net::Error>(net_error), input);
  }

  std::string provider_name_;
  std::vector<uint16_t> algorithm_preferences_;
  skfmodule * skf_module_=nullptr;
  DISALLOW_COPY_AND_ASSIGN(SKFPrivateKey);
};

void PinView::DeleteDelegate()
{
  // LOG(ERROR)<<"DeleteDelegate!";
  if(delegate_){
    // LOG(ERROR)<<"DeleteDelegate!delegate is to be reset.";
    delegate_->ContinueWithCertificate(nullptr, nullptr);
    delegate_.reset();
  }
  DialogDelegateView::DeleteDelegate();
}

bool PinView::Accept() {
  // skf_module_enumerator * glob_skf_enum = skf_module_enumerator::get_enumerator();
  if(/*!glob_skf_enum->get_module_by_issuer(issuer_,&glob_skf_module)*/!skf_module_->loadValidDev(issuer_)){
    errorlabel_->SetText(l10n_util::GetStringUTF16(IDS_NATIONAL_CIPHER_UKEY_STATE_ABSENT));
    errorlabel_->SetEnabledColor(SK_ColorRED);
    errorlabel_->SetVisible(true);
    return false;
  }

  base::string16 pin = name_field_->GetText();
  std::string strpin = base::UTF16ToUTF8(pin);
  int retcode = skf_module_->VerifyPin(strpin.c_str());
  if(SAR_OK != retcode){
    if(retcode == ssl_private_key_failure){
      errorlabel_->SetText(l10n_util::GetStringUTF16(IDS_NATIONAL_CIPHER_UKEY_STATE_UNKNOWN));
      errorlabel_->SetEnabledColor(SK_ColorRED);
      errorlabel_->SetVisible(true);
    }
    else{
      errorlabel_->SetText(l10n_util::GetStringUTF16(IDS_NATIONAL_CIPHER_PIN_PASSWORD_RRROR));
      errorlabel_->SetEnabledColor(SK_ColorRED);
      errorlabel_->SetVisible(true);
      name_field_->SelectAll(false); 
    }
    return false;
  }
  else{
    errorlabel_->SetEnabledColor(SK_ColorRED);
    errorlabel_->SetVisible(false); 
  }

  skfcontainer * ctn = skf_module_->get_valid_containner();

  uint8_t *buf = NULL;
  int cert_len = i2d_X509(ctn->cert[0], &buf);
  if (cert_len <= 0) {
    return false;
  }
  bssl::UniquePtr<CRYPTO_BUFFER> buffer = net::X509Certificate::CreateCertBufferFromBytes((const char *)buf, cert_len);
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  if(ctn->cert[1]!=nullptr){
    uint8_t *buf_enc = NULL;
    int cert_len_enc = i2d_X509(ctn->cert[1], &buf_enc);
    if (cert_len <= 0) {
      return false;
    }
    bssl::UniquePtr<CRYPTO_BUFFER> buffer_enc = net::X509Certificate::CreateCertBufferFromBytes((const char *)buf_enc, cert_len_enc);
    intermediates.push_back(std::move(buffer_enc));
  }
  scoped_refptr<net::X509Certificate> certificate = net::X509Certificate::CreateFromBuffer(std::move(buffer), std::move(intermediates));

  SKFPrivateKey* skf_private_key = new SKFPrivateKey("SKF UKey");
  skf_private_key->SetSkfModule(skf_module_);
  delegate_->ContinueWithCertificate(certificate.get(), skf_private_key);
  delegate_.reset();
  LOG(ERROR)<<"accept quit!";
  return true;
}

PinView::PinView() {
  DialogDelegate::set_use_custom_frame(true);
  DialogDelegate::SetButtons(ui::DIALOG_BUTTON_OK);
  DialogDelegate::SetDefaultButton(ui::DIALOG_BUTTON_OK);
  // DialogDelegate::SetButtonLabel(
  //     ui::DIALOG_BUTTON_OK, l10n_util::GetStringUTF16(IDS_TASK_MANAGER_KILL));

  // Avoid calling Accept() when closing the dialog, since Accept() here means
  // "kill task" (!).
  // TODO(ellyjones): Remove this once the Accept() override is removed from
  // this class.
  DialogDelegate::SetCloseCallback(base::DoNothing());
  set_margins(gfx::Insets(0,16,0,16));
  Init();
  // chrome::RecordDialogCreation(chrome::DialogIdentifier::TASK_MANAGER);
}

ui::ModalType PinView::GetModalType() const {
  return ui::MODAL_TYPE_CHILD;
}

void PinView::Init() {
  LOG(INFO)<<"PinView::Init";
   SetLayoutManager(std::make_unique<views::FillLayout>());
  auto pin_contents_view = std::make_unique<views::View>();
  views::GridLayout* layout = pin_contents_view->SetLayoutManager(
      std::make_unique<views::GridLayout>());

  constexpr int kColumnId = 0;
  ConfigureTextfieldStack(layout, kColumnId);

  // add by hanll, 增加标题, 2020/08/17, start
  AddTitleRow(layout,l10n_util::GetStringUTF16(IDS_NATIONAL_CIPHER_PIN_PASSWORD_NEEDED),kColumnId);
  name_field_ = AddFirstTextfieldRow(
      layout, l10n_util::GetStringUTF16(IDS_NATIONAL_CIPHER_PIN_PASSWORD_LABLE),
      kColumnId);
  name_field_->SetTextInputType(ui::TextInputType::TEXT_INPUT_TYPE_PASSWORD);
  // name_field_ = AddFirstTextfieldRow(
  //     layout, l10n_util::GetStringUTF16(IDS_BOOKMARK_BUBBLE_NAME_LABEL),
  //     kColumnId);
  // name_field_->SetText(GetBookmarkName());
  // name_field_->SetAccessibleName(l10n_util::GetStringUTF16(IDS_BOOKMARK_AX_BUBBLE_NAME_LABEL));
  errorlabel_ = AddMessageRow(layout,base::string16(),kColumnId);
  AddChildView(std::move(pin_contents_view));
  // AddAccelerator(ui::Accelerator(ui::VKEY_W, ui::EF_CONTROL_DOWN));
}

void PinView::CloseDialog() {
  // LOG(ERROR)<<"closedialog.";
  // base::debug::StackTrace().Print();
  GetWidget()->Close();
}

void PinView::OnCancel() {
  // Close the dialog if it is not currently being displayed
  if (!GetWidget()->IsVisible())
    CloseDialog();
}

base::OnceClosure PinView::GetCancellationCallback() {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  return base::BindOnce(&PinView::OnCancel,
                        weak_factory_.GetWeakPtr());
}

}  // namespace task_manager

namespace chrome {
  base::trace_event::TraceConfig::StringList *GetSSLSoDirectory(content::WebContents* web_contents)
  {
    auto browser = FindBrowserWithWebContents(web_contents);
    if (!browser) {
        return nullptr;
    }

    const base::DictionaryValue* dict = browser->profile()->GetPrefs()->GetDictionary(prefs::kUsbKeyDriverManager);
    if (dict->empty()){
        return nullptr;
    }

    const base::ListValue *listvalue;
    dict->GetList("driver_info", &listvalue);

    base::trace_event::TraceConfig::StringList *driver_list_directory = new base::trace_event::TraceConfig::StringList;
    std::string fullpath = "";
    for(size_t idx = 0; idx<listvalue->GetSize(); idx++) 
    {
      const base::DictionaryValue *value;
      listvalue->GetDictionary(idx, &value);
      value->GetString("path", &fullpath);
      if(fullpath.empty())
      {
        continue;
      }
      size_t pos = fullpath.find_last_of('/');
      std::string driver_directory = "";
      if(pos != std::string::npos)
      {
        driver_directory = fullpath.substr(0,pos);
      }

      if(std::find(driver_list_directory->begin(),driver_list_directory->end(),driver_directory) == driver_list_directory->end())
      {
        LOG(ERROR) << "driver directory = "<< driver_directory;
        driver_list_directory->push_back(driver_directory);
      }
    }
    return driver_list_directory;
  }
  
  base::trace_event::TraceConfig::StringList *GetSSLSoFullPath(content::WebContents* web_contents){
    auto browser = FindBrowserWithWebContents(web_contents);
    if (!browser) {
        return nullptr;
    }

    const base::DictionaryValue* dict = browser->profile()->GetPrefs()->GetDictionary(prefs::kUsbKeyDriverManager);
    if (dict->empty()){
        return nullptr;
    }

    const base::ListValue *listvalue;
    dict->GetList("driver_info", &listvalue);
    base::trace_event::TraceConfig::StringList *driver_list_fullpath = new base::trace_event::TraceConfig::StringList;
    driver_list_fullpath->clear();
    std::string fullpath = "";
    for(size_t idx = 0; idx<listvalue->GetSize(); idx++){
      const base::DictionaryValue *value;
      listvalue->GetDictionary(idx, &value);
      value->GetString("path", &fullpath);
      if(fullpath.empty()){
        continue;
      }

      if(std::find(driver_list_fullpath->begin(),driver_list_fullpath->end(),fullpath) == driver_list_fullpath->end()){
        driver_list_fullpath->push_back(fullpath);
      }
    }
    return driver_list_fullpath;
  }

  std::string GetSSLSoPath(content::WebContents* web_contents){

    auto browser = FindBrowserWithWebContents(web_contents);
      std::string path;
    if (!browser) {
        return "";
    }
      const base::DictionaryValue* dict = browser->profile()->GetPrefs()->GetDictionary(prefs::kUsbKeyDriverManager);
    if (dict->empty()){
        return "";
    }
    skf_module_enumerator * mods = skf_module_enumerator::get_enumerator();
    const base::ListValue *listvalue;
    dict->GetList("driver_info", &listvalue);
    for(size_t i = 0; i<listvalue->GetSize(); i++) {
      const base::DictionaryValue *value;
      listvalue->GetDictionary(i, &value);
      value->GetString("path", &path);
      LOG(ERROR) << "PATH = " << path;
      bool ret = mods->get_load_lib_result(path);
      if(ret){
          return path;
      }
    }
    return "";
  }

  bool CheckModulesAndDevices(content::WebContents* web_contents,
      net::SSLCertRequestInfo* cert_request_info,
      skfmodule** out_skf_module,X509_NAME **out_issuer)
  {
       //判断skf.so库是否设置 没设置返回false
    skf_module_enumerator * skf_enum = skf_module_enumerator::get_enumerator();

    base::trace_event::TraceConfig::StringList *driver_list_fullpath = GetSSLSoFullPath(web_contents);
    if(driver_list_fullpath == nullptr){
      return false;
    }
    
    // skf_enum->unInstallDrivers();

    for(std::string driver_fullpath:(*driver_list_fullpath)){
      if(!skf_enum->InstallDriver(driver_fullpath)){
        LOG(ERROR)<<"install driver error!";
      }
    }
    delete driver_list_fullpath;
    if(skf_enum->modules.empty()){
      return false;
    }

    skfmodule* skf_module = nullptr;
    X509_NAME *issuer = nullptr;
    for(std::string ca_name:cert_request_info->cert_authorities){
      const unsigned char *ca_tmp = reinterpret_cast<const unsigned char *>(ca_name.c_str());
      issuer = d2i_X509_NAME(NULL,&ca_tmp,ca_name.length());
      if(!issuer){
        continue;
      }

      if(!skf_enum->get_module_by_issuer(issuer,&skf_module)){
        LOG(ERROR)<<"get_module_by_issuer failed!";
        X509_NAME_free(issuer);
        issuer = nullptr;
        continue;
      }
      break;
    }

    if(skf_module == nullptr || issuer == nullptr){
      return false;
    }
    if(false == skf_module->validate()){
      return false;
    }
    *out_skf_module = skf_module;
    *out_issuer = issuer;
    return true;
  }

  base::OnceClosure ShowClientSSLPinDialog(
      content::WebContents* web_contents,
      net::SSLCertRequestInfo* cert_request_info,
      std::unique_ptr<content::ClientCertificateDelegate> delegate,
      skfmodule * in_skf_module,
      X509_NAME * in_issuer){
    //BrowserView* browser_view = BrowserView::GetBrowserViewForBrowser(browser);
    return task_manager1::PinView::Show(cert_request_info,web_contents,std::move(delegate),
      in_skf_module,in_issuer);
  }
  
}  // namespace chrome
#endif