#ifndef SKF_MANAGER_H
#define SKF_MANAGER_H
#ifndef OPENSSL_NO_GMTLS

#include "skf.h"
#include <string>
#include <list>
#include <vector>
#include <map>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <memory>


class skfmodule;
struct skfdev;
struct skfapp;
#define INVALIDHANDLE ((void*)-1)
struct skf_container_info
{
  DEVHANDLE devh            =INVALIDHANDLE;
  HAPPLICATION apph         =INVALIDHANDLE;
  HCONTAINER containnerh    =INVALIDHANDLE; 
  inline void reset(){
      devh=INVALIDHANDLE;
      apph=INVALIDHANDLE;
      containnerh=INVALIDHANDLE;
  }
  inline bool valid(){ return devh!=INVALIDHANDLE&&apph!=INVALIDHANDLE&&containnerh!=INVALIDHANDLE;}
};
struct skfcontainer
{
    HCONTAINER handle;
    std::string name;
    ULONG type;
    X509* cert[2]={0};//0 签名 1 加密
    skfcontainer(const std::string& name,const skfmodule* mod,const skfapp* app);
    X509* get_X509_from_container(HCONTAINER hc,BOOL SIGN,const skfmodule* mod);
    skfcontainer (skfcontainer&& other);
    skfcontainer (const skfcontainer& other)=delete;
    ~skfcontainer();
};
struct skfapp
{
    HAPPLICATION handle;
    std::string name;
    std::vector<skfcontainer> containers;
    skfapp(const std::string& appname,const skfmodule* mod,const skfdev* dev);
    void loadcontainer(const std::string& cname,const skfmodule* mod,const skfdev* dev);
};
struct skfdev
{
    DEVHANDLE handle;
    DEVINFO info;
    std::string name;
    std::vector<skfapp> apps;
    skfdev(const std::string& devname,const skfmodule* mod);
    void loadapp(const std::string& appname,const skfmodule* mod);
};

class skfmodule
{
public:
    ULONG (DEVAPI *SKF_EnumDev)(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);
    ULONG (DEVAPI *SKF_ConnectDev) (LPCSTR szName, DEVHANDLE *phDev);
    ULONG (DEVAPI *SKF_DisConnectDev) (DEVHANDLE hDev);
    ULONG (DEVAPI *SKF_CreateApplication)(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin, DWORD dwAdminPinRetryCount,LPSTR szUserPin, DWORD dwUserPinRetryCount,DWORD dwCreateFileRights, HAPPLICATION *phApplication);
    ULONG (DEVAPI *SKF_GetDevState)(LPSTR szDevName, ULONG *pulDevState);
    ULONG (DEVAPI *SKF_SetLabel) (DEVHANDLE hDev, LPSTR szLabel);
    ULONG (DEVAPI *SKF_GetDevInfo) (DEVHANDLE hDev, DEVINFO *pDevInfo);
    ULONG (DEVAPI *SKF_DevAuth) (DEVHANDLE hDev, BYTE *pbAuthData,ULONG ulLen);
    ULONG (DEVAPI *SKF_VerifyPIN) (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szPIN, ULONG *pulRetryCount);
    ULONG (DEVAPI *SKF_EnumApplication)(DEVHANDLE hDev, LPSTR szAppName,ULONG *pulSize);
    ULONG (DEVAPI *SKF_OpenApplication)(DEVHANDLE hDev, LPCSTR szAppName, HAPPLICATION *phApplication);
    ULONG (DEVAPI *SKF_CloseApplication)(HAPPLICATION hApplication);
    ULONG (DEVAPI *SKF_CreateContainer) (HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);
    ULONG (DEVAPI *SKF_DeleteContainer)(HAPPLICATION hApplication, LPSTR szContainerName);
    ULONG (DEVAPI *SKF_EnumContainer) (HAPPLICATION hApplication, LPSTR szContainerName, ULONG *pulSize);
    ULONG (DEVAPI *SKF_OpenContainer)(HAPPLICATION hApplication,LPCSTR szContainerName,HCONTAINER *phContainer);
    ULONG (DEVAPI *SKF_CloseContainer)(HCONTAINER hContainer);
    ULONG (DEVAPI *SKF_DeleteApplication)(DEVHANDLE hDev, LPSTR szAppName);
    ULONG (DEVAPI *SKF_ImportCertificate)(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG ulCertLen);
    ULONG (DEVAPI *SKF_ExportCertificate)(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG *pulCertLen);
    ULONG (DEVAPI *SKF_GenRandom) (DEVHANDLE hDev, BYTE *pbRandom,ULONG ulRandomLen);
    ULONG (DEVAPI *SKF_GenECCKeyPair) (HCONTAINER hContainer, ULONG ulAlgId,ECCPUBLICKEYBLOB *pBlob);
    ULONG (DEVAPI *SKF_ECCSignData) (HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature);
    ULONG (DEVAPI *SKF_ExtECCVerify) (DEVHANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob,BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
    ULONG (DEVAPI *SKF_ExportPublicKey) (HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbBlob, ULONG* pulBlobLen);
    ULONG (DEVAPI *SKF_DigestInit)(DEVHANDLE hDev, ULONG ulAlgID,  ECCPUBLICKEYBLOB *pPubKey, unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash);
    ULONG (DEVAPI *SKF_Digest) (HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen);
    ULONG (DEVAPI *SKF_DigestUpdate) (HANDLE hHash, BYTE *pbData, ULONG  ulDataLen);
    ULONG (DEVAPI *SKF_DigestFinal) (HANDLE hHash, BYTE *pHashData, ULONG  *pulHashLen);
    ULONG (DEVAPI *SKF_ChangeDevAuthKey)(DEVHANDLE hDev, BYTE *pbKeyValue, ULONG ulKeyLen);
    ULONG (DEVAPI *SKF_SetSymmKey) (DEVHANDLE hDev, BYTE* pbKey, ULONG ulAlgID, HANDLE* phKey);
    ULONG (DEVAPI *SKF_EncryptInit) (HANDLE hKey, BLOCKCIPHERPARAM EncryptParam);
    ULONG (DEVAPI *SKF_Encrypt)(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);
    ULONG (DEVAPI *SKF_EncryptUpdate)(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);
    ULONG (DEVAPI *SKF_EncryptFinal)(HANDLE hKey, BYTE *pbEncryptedData, ULONG *ulEncryptedDataLen );
    ULONG (DEVAPI* SKF_GetContainerType)(HCONTAINER hContainer, ULONG *pulContainerType);

    OPENSSL_EXPORT skfmodule(const char* module);
    OPENSSL_EXPORT skfmodule(const skfmodule& module);
    OPENSSL_EXPORT skfmodule();
    ~skfmodule();
    skfmodule& operator=(const skfmodule& skf);
    void loadSymbols();
    OPENSSL_EXPORT int loadDevs();
    void unloadDevs();
    bool loadValidDev(X509_NAME* issuer);
    bool loadDev(const std::string& devname);
    
    skfcontainer* get_containner(const std::string& devname,const std::string& appname,const std::string&container_name,skf_container_info* info);
    skfcontainer* get_containner(const skf_container_info& info);
    OPENSSL_EXPORT skfcontainer* get_first_valid_containner(skf_container_info& info,X509_NAME *issuer);
    skfcontainer* get_valid_containner();
    OPENSSL_EXPORT int skf_privatekey_sign(uint8_t *out, size_t *out_len,
                            size_t max_out,
                            uint16_t signature_algorithm,
                            const uint8_t *in, size_t in_len);

    OPENSSL_EXPORT bool validate();
    OPENSSL_EXPORT int VerifyPin(const char* pin);
    OPENSSL_EXPORT int  enumDevicesCount();

public:
    std::vector<skfdev> devs;
    void * handle=nullptr;
    std::string name;
    skf_container_info validInfo_;
    ukey_verify_info validNameInfo_;
    skfcontainer * validContainer_;
};

SSL_PRIVATE_KEY_METHOD* get_skf_method();
class skf_module_enumerator
{
    private:
    skf_module_enumerator();
    ~skf_module_enumerator()=delete;
    static skf_module_enumerator* instance;
    public:
    static skf_module_enumerator* get_enumerator();
    std::map<std::string,skfmodule*> modules;
    bool InstallDriver(const std::string& path);
    void unInstallDrivers();
    bool EnumDirectory(const std::string& path);
    const std::map<std::string,skfmodule*>& get_modules();
    bool get_load_lib_result(const std::string& file);
    //check lib valid
    bool check_lib_valid(const std::string& file);
    skfcontainer* get_container_by_issuer(X509_NAME* issuer,skfmodule** module,skf_container_info& cinfo,ukey_verify_info& uvinfo,int type);
    bool get_module_by_issuer(X509_NAME* issuer,skfmodule** module);
};

#endif
#endif