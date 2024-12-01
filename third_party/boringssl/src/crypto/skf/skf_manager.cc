#ifndef OPENSSL_NO_GMTLS

#include "skf_manager.h"
#include <dlfcn.h>
#include <string.h>
#include <dirent.h>
#include <openssl/ssl.h>
#include <openssl/sm2.h>
#include <openssl/x509.h>
#include <unistd.h>
#include "../../ssl/internal.h"
#include <iostream>

static int split_names(const char *name_list, const size_t list_len,std::vector<std::string>& names){
    const char *end = name_list + list_len;
    size_t len;
    int num = 0;

    while (name_list < end) {
        len = strlen(name_list);
        if (len) {
            names.push_back(name_list);
            num++;
            name_list += len + 1;
        } else {
            name_list++;
        }
    }
    return num;
}

void skfmodule::loadSymbols(){
    if(handle==nullptr){
        fprintf(stderr,"loadSymbols,handle is null.");
        return;
    }
    SKF_EnumDev=(SKF_EnumDev_type)dlsym(handle,"SKF_EnumDev");
    SKF_ConnectDev=(SKF_ConnectDev_type)dlsym(handle,"SKF_ConnectDev");
    SKF_DisConnectDev=(SKF_DisConnectDev_type)dlsym(handle,"SKF_DisConnectDev");
    SKF_CreateApplication=(SKF_CreateApplication_type)dlsym(handle,"SKF_CreateApplication");
    SKF_GetDevState=(SKF_GetDevState_type)dlsym(handle,"SKF_GetDevState");
    SKF_SetLabel=(SKF_SetLabel_type)dlsym(handle,"SKF_SetLabel");
    SKF_GetDevInfo=(SKF_GetDevInfo_type)dlsym(handle,"SKF_GetDevInfo");
    SKF_DevAuth=(SKF_DevAuth_type)dlsym(handle,"SKF_DevAuth");
    SKF_VerifyPIN=(SKF_VerifyPIN_type)dlsym(handle,"SKF_VerifyPIN");
    SKF_EnumApplication=(SKF_EnumApplication_type)dlsym(handle,"SKF_EnumApplication");
    SKF_OpenApplication=(SKF_OpenApplication_type)dlsym(handle,"SKF_OpenApplication");
    SKF_CloseApplication=(SKF_CloseApplication_type)dlsym(handle,"SKF_CloseApplication");
    SKF_CreateContainer=(SKF_CreateContainer_type)dlsym(handle,"SKF_CreateContainer");
    SKF_DeleteContainer=(SKF_DeleteContainer_type)dlsym(handle,"SKF_DeleteContainer");
    SKF_EnumContainer=(SKF_EnumContainer_type)dlsym(handle,"SKF_EnumContainer");
    SKF_OpenContainer=(SKF_OpenContainer_type)dlsym(handle,"SKF_OpenContainer");
    SKF_CloseContainer=(SKF_CloseContainer_type)dlsym(handle,"SKF_CloseContainer");
    SKF_DeleteApplication=(SKF_DeleteApplication_type)dlsym(handle,"SKF_DeleteApplication");
    SKF_ImportCertificate=(SKF_ImportCertificate_type)dlsym(handle,"SKF_ImportCertificate");
    SKF_ExportCertificate=(SKF_ExportCertificate_type)dlsym(handle,"SKF_ExportCertificate");
    SKF_GenRandom=(SKF_GenRandom_type)dlsym(handle,"SKF_GenRandom");
    SKF_GenECCKeyPair=(SKF_GenECCKeyPair_type)dlsym(handle,"SKF_GenECCKeyPair");
    SKF_ECCSignData=(SKF_ECCSignData_type)dlsym(handle,"SKF_ECCSignData");
    SKF_ExtECCVerify=(SKF_ExtECCVerify_type)dlsym(handle,"SKF_ExtECCVerify");
    SKF_ExportPublicKey=(SKF_ExportPublicKey_type)dlsym(handle,"SKF_ExportPublicKey");
    SKF_DigestInit=(SKF_DigestInit_type)dlsym(handle,"SKF_DigestInit");
    SKF_Digest=(SKF_Digest_type)dlsym(handle,"SKF_Digest");
    SKF_DigestUpdate=(SKF_DigestUpdate_type)dlsym(handle,"SKF_DigestUpdate");
    SKF_DigestFinal=(SKF_DigestFinal_type)dlsym(handle,"SKF_DigestFinal");
    SKF_ChangeDevAuthKey=(SKF_ChangeDevAuthKey_type)dlsym(handle,"SKF_ChangeDevAuthKey");
    SKF_SetSymmKey=(SKF_SetSymmKey_type)dlsym(handle,"SKF_SetSymmKey");
    SKF_EncryptInit=(SKF_EncryptInit_type)dlsym(handle,"SKF_EncryptInit");
    SKF_Encrypt=(SKF_Encrypt_type)dlsym(handle,"SKF_Encrypt");
    SKF_EncryptUpdate=(SKF_EncryptUpdate_type)dlsym(handle,"SKF_EncryptUpdate");
    SKF_EncryptFinal=(SKF_EncryptFinal_type)dlsym(handle,"SKF_EncryptFinal");
    SKF_GetContainerType=(SKF_GetContainerType_type)dlsym(handle,"SKF_GetContainerType");
}

skfmodule::skfmodule(const skfmodule& module){
    if(handle!=NULL){
        dlclose(handle);
    }
    handle=dlopen(module.name.c_str(),RTLD_NOW);
    loadSymbols();
}

skfmodule& skfmodule::operator=(const skfmodule& mod){
    if(handle!=NULL){
        dlclose(handle);
    }
    handle=dlopen(mod.name.c_str(),RTLD_NOW);
    if(handle==nullptr)
        return *this;
    loadSymbols();
    return *this;
}

skfmodule::skfmodule(const char* module){
    name=module;
    handle=dlopen(module,RTLD_NOW);
    if(handle==nullptr)
    {
        perror("dlopen:");
        return;
    }
        
    loadSymbols();
}

int skfmodule::loadDevs(){
    unloadDevs();
    int devCount = 0;
    if(!handle){
        fprintf(stderr,"loadDevs handle is null.\n");
        return devCount;
    }

    if(SKF_EnumDev==NULL){
        fprintf(stderr,"loadDevs SKF_EnumDev is null.\n");
        return devCount;
    }

    ULONG rv, listLen = 0;
    rv = SKF_EnumDev(FALSE, nullptr, &listLen);
    if (rv != SAR_OK){
        fprintf(stderr,"loadDevs SKF_EnumDev return error:%ld\n",rv);
        return devCount;
    }

    char *devList = (char*)malloc(listLen);
    memset(devList,0,listLen);
    rv = SKF_EnumDev(FALSE, devList, &listLen);
    if (rv != SAR_OK) {
        fprintf(stderr,"loadDevs SKF_EnumDev 2end return error:%ld\n",rv);
        return devCount;
    }
    std::vector<std::string> namelist;
    int co=split_names(devList,listLen,namelist);
    free(devList);
    for(int i=0;i<co;i++){
        if( true == loadDev(namelist[i])){
            ++devCount;
        }
    }
    fprintf(stderr,"dev count is :%d\n",devCount);
    return devCount;
}

void skfmodule::unloadDevs(){
    if(!devs.empty()){
        devs.clear();
    }
}

bool skfmodule::loadValidDev(X509_NAME* issuer)
{
    if(issuer == nullptr){
        return false;
    }
    // fprintf(stderr,"loadValidDev this is :%ld\n",this);
    // unloadDevs();
    if(loadDevs() == 0){
        fprintf(stderr,"get_module_by_issuer,devs' size is:%ld\n",devs.size());
        return false;
    }
    
    for(auto& dev:devs){
        for(auto&app:dev.apps){
            for(auto& ctn:app.containers){
                if(ctn.cert[0]==nullptr){
                    fprintf(stderr,"cert is nullptr!\n");
                    continue;
                }
                if(X509_NAME_cmp(ctn.cert[0]->cert_info->issuer,issuer)!=0){
                    fprintf(stderr,"cert0's issuer is not equal!\n");
                    continue;
                }
                if(ctn.cert[1]!=nullptr){
                    if(X509_NAME_cmp(ctn.cert[1]->cert_info->issuer,issuer)!=0){
                        fprintf(stderr,"cert1's issuer is not equal!\n");
                        continue;
                    }
                }
                else{
                    continue;
                }
                
                // strncpy(validNameInfo_.mod_name,name.c_str(),SKF_NAME_MAX_LENGTH);
                // validNameInfo_.mod_name[SKF_NAME_MAX_LENGTH-1]='\0';

                validInfo_.devh=dev.handle;
                strncpy(validNameInfo_.dev_name,dev.name.c_str(),SKF_NAME_MAX_LENGTH);
                validNameInfo_.dev_name[SKF_NAME_MAX_LENGTH-1]='\0';
                
                validInfo_.apph=app.handle;
                strncpy(validNameInfo_.app_name,app.name.c_str(),SKF_NAME_MAX_LENGTH);
                validNameInfo_.app_name[SKF_NAME_MAX_LENGTH-1]='\0';
                
                validInfo_.containnerh = ctn.handle;
                strncpy(validNameInfo_.container_name,ctn.name.c_str(),SKF_NAME_MAX_LENGTH);
                validNameInfo_.container_name[SKF_NAME_MAX_LENGTH-1]='\0';
                
                validContainer_ = &ctn;
                return true;
            }
        }
    }
    return false;
}

bool skfmodule::loadDev(const std::string& devname){
    devs.emplace_back(devname,this);
    skfdev& newdev=devs.back();
    if(newdev.handle==nullptr){
        devs.pop_back();
        return false;
    }
    return true;
}

skfmodule::skfmodule(){
    handle=nullptr;
}

skfmodule::~skfmodule(){
    if(handle!=nullptr)
    {
        dlclose(handle);
    }
}

skfcontainer* skfmodule::get_containner(const skf_container_info& info){
    for(auto& dev:devs){
        if(dev.handle==info.devh){
            for(auto& app:dev.apps){
                if(app.handle==info.apph){
                    for(auto& c:app.containers){
                        if(c.handle==info.containnerh)
                            return &c;
                    }
                    return nullptr;
                }
            }
            return nullptr;
        }
    }
    return nullptr;
}

skfcontainer* skfmodule::get_containner(const std::string& devname,const std::string& appname,
    const std::string&containername,skf_container_info* info){
    if(devs.size()==0)
        return nullptr;
    skfdev* dev=&devs[0];
    bool got=false;
    if(devname!=""){
        for(auto& dev_it:devs){
            if(dev_it.name==devname){
                dev=&dev_it;
                got=true;
                break;
            }
        }
        if(!got)
            return nullptr;
    }
    if(dev==nullptr)
        return nullptr;
    if(dev->apps.size()==0)
        return nullptr;
    skfapp* app=&(dev->apps[0]);
    if(appname!=""){
        got=false;
        for(auto& app_it:dev->apps){
            if(app_it.name==appname){
                app=&app_it;
                got=true;
                break;
            }
        }
        if(!got)
            return nullptr;
    }
    if(app==nullptr)
        return nullptr;


    if(app->containers.size()==0)
        return nullptr;
    skfcontainer* res=&(app->containers[0]);
    if(containername!=""){
        got=false;
        for(auto& con_it:app->containers){
            if(con_it.name==containername){
                res=&con_it;
                got=true;
                break;
            }
        }
    }

    if(res!=nullptr&& info!=nullptr){
    info->devh=dev->handle;
    info->apph=app->handle;
    info->containnerh=res->handle;
    }
    else if(res==nullptr&& info!=nullptr){
        info->reset();
    }
    
    return res;
}

skfcontainer* skfmodule::get_valid_containner(){
    return validContainer_;
}

skfcontainer* skfmodule::get_first_valid_containner(skf_container_info& info,X509_NAME *issuer){
    info.reset();
    for(int ix = 0; ix<devs.size(); ix++){
        skfdev* dev=&devs[ix];
        for(int iy = 0; iy<dev->apps.size(); iy++){
            skfapp* app=&(dev->apps[iy]);
            for(int iz = 0; iz<app->containers.size();iz++){
                skfcontainer* ctn=&(app->containers[iz]);
                if(ctn->cert[0] == nullptr || ctn->cert[1] == nullptr){
                    continue;
                }
                fprintf(stderr,"get_first_valid_containner get it.");
                info.devh=dev->handle;
                info.apph=app->handle;
                info.containnerh=ctn->handle;
                return ctn;
            }
        }
    }
    return nullptr;
}

bool skfmodule::validate(){
    if(handle!=NULL && SKF_EnumDev!=NULL&&SKF_ConnectDev!=NULL&&SKF_DisConnectDev!=NULL&&SKF_CreateApplication!=NULL
    &&SKF_GetDevState!=NULL&&SKF_SetLabel!=NULL&&SKF_GetDevInfo!=NULL&&SKF_DevAuth!=NULL&&SKF_VerifyPIN!=NULL&&
    SKF_EnumApplication!=NULL&&SKF_OpenApplication!=NULL&&SKF_CloseApplication!=NULL&&SKF_CreateContainer!=NULL&&SKF_DeleteContainer!=NULL&&SKF_EnumContainer!=NULL&&
    SKF_OpenContainer!=NULL&&SKF_CloseContainer!=NULL&&SKF_DeleteApplication!=NULL&&SKF_ImportCertificate!=NULL&&SKF_ExportCertificate!=NULL&&SKF_GenRandom!=NULL&&
    SKF_GenECCKeyPair!=NULL&&SKF_ECCSignData!=NULL&&SKF_ExportPublicKey!=NULL&&SKF_DigestInit!=NULL&&SKF_Digest!=NULL&&
    SKF_DigestUpdate!=NULL&&SKF_DigestFinal!=NULL&&SKF_ChangeDevAuthKey!=NULL&&SKF_SetSymmKey!=NULL&&SKF_EncryptInit!=NULL&&SKF_Encrypt!=NULL&&
    SKF_EncryptUpdate!=NULL&&SKF_EncryptFinal!=NULL&&SKF_GetContainerType!=NULL){
        return true;
    }
    return false;
}

int skfmodule::VerifyPin(const char* pin){
     if(!handle)
        return ssl_private_key_failure;
        
    ULONG retry = -1;
    return SKF_VerifyPIN(validInfo_.apph,USER_TYPE,(LPSTR)pin,&retry);
}

int skfmodule::enumDevicesCount(){
    if(!handle)
        return -1;

    if(SKF_EnumDev==NULL)
        return -2;

    ULONG rv, listLen;
    CHAR devList[512], buf[128];

    listLen = sizeof (buf) / sizeof (CHAR);
    rv = SKF_EnumDev(FALSE, devList, &listLen);
    if (rv != SAR_OK){
        return -1;
    }
    std::vector<std::string> namelist;
    int co=split_names(devList,listLen,namelist);

    return co;
}

skfdev::skfdev(const std::string& devname,const skfmodule* mod){
    name=devname;
    ULONG rv = mod->SKF_ConnectDev(devname.c_str(), &handle);
    if (rv != SAR_OK){
            return;
    }
    mod->SKF_GetDevInfo(handle, &info);
    ULONG length=0;
    mod->SKF_EnumApplication(handle,nullptr,&length);
    char *appname = (char*)malloc(length);
    memset(appname,0,length);
    mod->SKF_EnumApplication(handle,appname,&length); 
    std::vector<std::string> namelist;
    int co=split_names(appname,length,namelist);
    free(appname);
    // apps.clear();
    for(int i=0;i<co;i++){
        loadapp(namelist[i],mod);
    }
}

void skfdev::loadapp(const std::string& appname,const skfmodule* mod)
{
    apps.emplace_back(appname,mod,this);
    skfapp& newapp=apps.back();
    if(newapp.handle==nullptr){
        apps.pop_back();
    }
}

skfapp::skfapp(const std::string& appname,const skfmodule* mod,const skfdev* dev){
    ULONG rv=mod->SKF_OpenApplication(dev->handle,appname.c_str(),&handle);
    if(rv!=SAR_OK)
        return;
    
    name=appname;
    ULONG length=0;
    mod->SKF_EnumContainer(handle,nullptr,&length);
    char *container_names = (char*)malloc(length);
    memset(container_names,0,length);
    mod->SKF_EnumContainer(handle,container_names,&length); 
    std::vector<std::string> namelist;
    int co=split_names(container_names,length,namelist);
    free(container_names);
    // containers.clear();
    for(int i=0;i<co;i++){
        loadcontainer(namelist[i],mod,dev);
    }
}

void skfapp::loadcontainer(const std::string& cname,const skfmodule* mod,const skfdev* dev){
    
    containers.emplace_back(cname,mod,this);
    skfcontainer & con=containers.back();
    if(con.handle==nullptr){
        containers.pop_back();
    }
}

skfcontainer::skfcontainer (skfcontainer&& other)
        :handle(other.handle)
        ,name(other.name)
        ,type(other.type){
        cert[0]=other.cert[0];
        cert[1]=other.cert[1];        
        other.cert[0]=nullptr;
        other.cert[1]=nullptr;
}

skfcontainer::~skfcontainer(){
    if(cert[0]!=nullptr)
        X509_free(cert[0]);
    if(cert[1]!=nullptr)
        X509_free(cert[1]);
}

skfcontainer::skfcontainer(const std::string& cname,const skfmodule* mod,const skfapp* app){
    handle=0;
    // if(cname.c_str()){
    //     fprintf(stderr,"skfcontainer entered.%s\n",cname.c_str());
    // }
    if((mod->SKF_OpenContainer(app->handle,cname.c_str(),&handle))!=SAR_OK)
        return;
    mod->SKF_GetContainerType(handle,&type);
    cert[0]=(get_X509_from_container(handle,TRUE,mod));
    cert[1]=(get_X509_from_container(handle,FALSE,mod));
    name=cname;
}

X509*skfcontainer::get_X509_from_container(HCONTAINER hc,BOOL SIGN,const skfmodule* mod){
    ULONG cert_sz=0;
    if(mod->SKF_ExportCertificate(hc,SIGN,NULL,&cert_sz)==SAR_OK){
        if(cert_sz == 0){
            fprintf(stderr,"get_X509_from_container.get failed.cert size is 0\n");
            return NULL;
        }
        BYTE* pSCert=0;
        pSCert=(BYTE*)malloc(cert_sz);
        memset(pSCert,0,cert_sz);
        if(mod->SKF_ExportCertificate(hc,SIGN,pSCert,&cert_sz)==SAR_OK){
            X509* m_pX509=NULL;
            m_pX509 = d2i_X509(NULL, (unsigned char const **)&pSCert, cert_sz);
            free(pSCert-cert_sz);
            return m_pX509;
        }
        else{
            free(pSCert);
            fprintf(stderr,"get_X509_from_container.The second try failed.\n");
            return NULL;
        }
    }
    else{
        fprintf(stderr,"get_X509_from_container.The first try failed.\n");
        return NULL;
    }
}

static int ECDSA_SIG_set_ECCSIGNATUREBLOB(ECDSA_SIG *sig, const ECCSIGNATUREBLOB *blob){

	if (!(sig->r = BN_bin2bn(blob->r, sizeof(blob->r), sig->r))) {
		return 0;
	}

	if (!(sig->s = BN_bin2bn(blob->s, sizeof(blob->s), sig->s))) {
		return 0;
	}

	return 1;
}

static ECDSA_SIG *ECDSA_SIG_new_from_ECCSIGNATUREBLOB(const ECCSIGNATUREBLOB *blob){
	ECDSA_SIG *ret = NULL;

	if (!(ret = ECDSA_SIG_new())) {
		return NULL;
	}

	if (!ECDSA_SIG_set_ECCSIGNATUREBLOB(ret, blob)) {
		ECDSA_SIG_free(ret);
		return NULL;
	}

	return ret;
}


static int i2d_ECCSIGNATUREBLOB(ECCSIGNATUREBLOB *a, unsigned char **pp){
	int ret;
	ECDSA_SIG *sig = NULL;

	if (!(sig = ECDSA_SIG_new_from_ECCSIGNATUREBLOB(a))) {
		return 0;
	}

	ret = i2d_ECDSA_SIG(sig, pp);
	ECDSA_SIG_free(sig);
	return ret;
}

static BOOL default_pin(char PIN[20],const ukey_verify_info* info){
   // strcpy(PIN,"88888888");
    //printf("default_pin");
    return TRUE;
}

static enum ssl_private_key_result_t skf_sign(SSL *ssl, uint8_t *out, size_t *out_len,
                                        size_t max_out,
                                        uint16_t signature_algorithm,
                                        const uint8_t *in, size_t in_len){
    skfmodule* mod=ssl->ctx->module;
    if(!mod->handle)
        return ssl_private_key_failure;
    skf_container_info& info=ssl->ctx->container;
    if(info.apph==INVALIDHANDLE||info.containnerh==INVALIDHANDLE||info.devh==INVALIDHANDLE)
        return ssl_private_key_failure;
    ECCSIGNATUREBLOB blob;
    HANDLE hhash;
    skfcontainer* c=mod->get_containner(info);

    int res=mod->SKF_DigestInit(info.devh,SGD_SM3,nullptr,nullptr,0,&hhash);
    if(res!=SAR_OK){
        printf("SKF_DigestInit %x\n",res);
        return ssl_private_key_failure;
    }
    if(c==nullptr)
        return ssl_private_key_failure;
        
    EVP_PKEY* pkey=X509_get_pubkey(c->cert[0]);
    if(/*ssl->gm_implement== tassl_like &&*/ NID_sm2 == EC_GROUP_get_curve_name(EC_KEY_get0_group(pkey->pkey.ec))){
        uint8_t *psm2Z = NULL;
        psm2Z = (uint8_t *)OPENSSL_malloc(128);
        size_t z_len = 128;
        ECDSA_sm2_get_Z(pkey->pkey.ec, EVP_sm3(), "1234567812345678", 16, psm2Z, &z_len);
        res=mod->SKF_DigestUpdate(hhash,psm2Z,z_len);
        if(res!=SAR_OK){
            printf("SKF_DigestUpdate %x\n",res);
            OPENSSL_free(psm2Z);
            return ssl_private_key_failure;
        }
        OPENSSL_free(psm2Z);
    }
    res=mod->SKF_DigestUpdate(hhash,(BYTE*)in,in_len);
    if(res!=SAR_OK){
        printf("SKF_DigestUpdate %x\n",res);
        return ssl_private_key_failure;
    }
    ULONG hashlen=EVP_MAX_MD_SIZE;
    uint8_t md[EVP_MAX_MD_SIZE]={0};
    res=mod->SKF_DigestFinal(hhash,md,&hashlen);
    if(res!=SAR_OK){
        printf("SKF_DigestFinal %x\n",res);
        return ssl_private_key_failure;
    }
    res=mod->SKF_ECCSignData(info.containnerh,(BYTE*)md,hashlen,&blob);
    if(res!=SAR_OK){
        printf("SKF_ECCSignData %x,try to verifypin and retry\n",res);
        if(res==SAR_FAIL||res==SAR_USER_NOT_LOGGED_IN){
            if(ssl->get_ukey_pin_callback==nullptr)
                ssl->get_ukey_pin_callback=default_pin;
            ULONG retry = -1;
            ULONG verify_result=SAR_OK;
            do{
                char PIN[20] = {0};
                if(ssl->get_ukey_pin_callback(PIN,&(ssl->ctx->uvinfo))==FALSE){
                    return ssl_private_key_failure;
                }
                ssl->ctx->uvinfo.retry=retry;
                verify_result = ssl->ctx->module->SKF_VerifyPIN(ssl->ctx->container.apph,USER_TYPE,(LPSTR)PIN,&retry);
                if(verify_result!=SAR_OK){
                    printf("SKF_VerifyPIN %p\n",(void*)verify_result);
                }
            }while(SAR_OK != verify_result && retry != 0);
            if(SAR_OK!=verify_result){
                return ssl_private_key_failure;
            }
            res=mod->SKF_ECCSignData(info.containnerh,(BYTE*)md,hashlen,&blob);
            if(res!=SAR_OK)
                return ssl_private_key_failure;
        }
    }
    uint8_t sig[512];
    uint8_t* sigptr=sig;
    int siglen=i2d_ECCSIGNATUREBLOB(&blob,&sigptr);
    memcpy(out,sig,siglen);
    *out_len=siglen;
    return ssl_private_key_success;
}


int skfmodule::skf_privatekey_sign(uint8_t *out, size_t *out_len,
                            size_t max_out,
                            uint16_t signature_algorithm,
                            const uint8_t *in, size_t in_len)
{
    if(!handle)
        return ssl_private_key_failure;

    ECCSIGNATUREBLOB blob;
    HANDLE hhash;

    int res= SKF_DigestInit(validInfo_.devh,SGD_SM3,nullptr,nullptr,0,&hhash);
    if(res!=SAR_OK)
    {
        printf("SKF_DigestInit %x\n",res);
        return ssl_private_key_failure;
    }

    if(validContainer_==nullptr)
        return ssl_private_key_failure;
        
    EVP_PKEY* pkey=X509_get_pubkey(validContainer_->cert[0]);
    if( NID_sm2 == EC_GROUP_get_curve_name(EC_KEY_get0_group(pkey->pkey.ec)))
    {
        uint8_t *psm2Z = NULL;
        psm2Z = (uint8_t *)OPENSSL_malloc(128);
        size_t z_len = 128;
        ECDSA_sm2_get_Z(pkey->pkey.ec, EVP_sm3(), "1234567812345678", 16, psm2Z, &z_len);
        res=SKF_DigestUpdate(hhash,psm2Z,z_len);
        if(res!=SAR_OK)
        {
            printf("SKF_DigestUpdate %x\n",res);
            OPENSSL_free(psm2Z);
            return ssl_private_key_failure;
        }
        OPENSSL_free(psm2Z);
    }
    res=SKF_DigestUpdate(hhash,(BYTE*)in,in_len);
    if(res!=SAR_OK)
    {
        printf("SKF_DigestUpdate %x\n",res);
        return ssl_private_key_failure;
    }
    ULONG hashlen=EVP_MAX_MD_SIZE;
    uint8_t md[EVP_MAX_MD_SIZE]={0};
    res=SKF_DigestFinal(hhash,md,&hashlen);
    if(res!=SAR_OK)
    {
        printf("SKF_DigestFinal %x\n",res);
        return ssl_private_key_failure;
    }
    res=SKF_ECCSignData(validInfo_.containnerh,(BYTE*)md,hashlen,&blob);
    if(res!=SAR_OK)
    {
        return ssl_private_key_failure;
    }
    uint8_t sig[512];
    uint8_t* sigptr=sig;
    int siglen=i2d_ECCSIGNATUREBLOB(&blob,&sigptr);
    memcpy(out,sig,siglen);
    *out_len=siglen;
    return ssl_private_key_success;
}

static enum ssl_private_key_result_t skf_decrypt(SSL *ssl, uint8_t *out,size_t *out_len, size_t max_out,const uint8_t *in, size_t in_len)
{
    return ssl_private_key_failure;
}
static enum ssl_private_key_result_t skf_complete(SSL *ssl, uint8_t *out,
                                            size_t *out_len, size_t max_out)
{
    return ssl_private_key_failure;
}
SSL_PRIVATE_KEY_METHOD skf_method=
{
    skf_sign,skf_decrypt,skf_complete
};
SSL_PRIVATE_KEY_METHOD* get_skf_method()
{
    return &skf_method;
}
skf_module_enumerator::skf_module_enumerator()
{
}
skf_module_enumerator* skf_module_enumerator::instance=nullptr;
skf_module_enumerator* skf_module_enumerator::get_enumerator()
{
    if(!instance)
    {
        instance=new skf_module_enumerator();
    }
    return instance;
}
static bool so_name_check(const char* name)
{
    if(name==nullptr)
        return false;
    int len=strlen(name);
    if(len<7)
        return false;
    if(memcmp(name,"lib",3)==0)
    {
        for(int i=3;i<len-2;i++)
        {
            if(memcmp(name+i,".so",3)==0)
                return true;
        }
    }
    return false;
}
const std::map<std::string,skfmodule*>& skf_module_enumerator::get_modules()
{
    return modules;
}


void skf_module_enumerator::unInstallDrivers(){
    if(modules.empty()){
        return;
    }

    for(std::pair<std::string,skfmodule*> mod : modules){
        delete mod.second;
    }
    modules.clear();
}

bool skf_module_enumerator::InstallDriver(const std::string& path){
    if(modules.count(path)){
        fprintf(stderr,"driver is already installed:%s\n",path.c_str());
        return true;
    }

    skfmodule* mod=new skfmodule(path.c_str());
    if(mod->validate()){
        modules.insert(std::pair<std::string,skfmodule*>(path,mod));
        return true;
    }
    else{
        delete mod;
        return false;
    }
}

bool skf_module_enumerator::EnumDirectory(const std::string& path){
    for(auto it:modules){
        if(it.second!=nullptr){
            delete it.second;
        }
    }
    modules.clear();
    DIR* dir=opendir(path.c_str());
    if(dir==NULL)
        return false;
    dirent* ent;
    while(ent=readdir(dir),ent!=NULL){
        if(ent->d_type==DT_DIR)
            continue;
        if(!so_name_check(ent->d_name))
            continue;
        skfmodule* mod=new skfmodule(std::string(path+"/"+ent->d_name).c_str());
        if(mod->validate())
            modules.insert(std::pair<std::string,skfmodule*>(std::string(ent->d_name),mod));
        else
            delete mod;
    }
    closedir(dir);
    return true;
}


bool skf_module_enumerator::get_module_by_issuer(X509_NAME* issuer,skfmodule** module){
    if(issuer == nullptr){
        return false;
    }
    *module=nullptr;
    if(modules.size()==0){
        fprintf(stderr,"modules' size is zero!\n");
        return false;
    }
    fprintf(stderr,"modules'size is :%ld\n",modules.size());
    for(auto& it : modules){
        if(it.second == nullptr){
            continue;
        }
        skfmodule* mod=it.second;
        
        if(mod->loadDevs() == 0){
            fprintf(stderr,"get_module_by_issuer,devs' size is:%ld\n",mod->devs.size());
            continue;
        }
        
        for(auto& dev:mod->devs){
            for(auto&app:dev.apps){
                for(auto& ctn:app.containers){
                    if(ctn.cert[0]==nullptr){
                        fprintf(stderr,"cert is nullptr!\n");
                        continue;
                    }
                    if(X509_NAME_cmp(ctn.cert[0]->cert_info->issuer,issuer)!=0){
                        fprintf(stderr,"cert0's issuer is not equal!\n");
                        continue;
                    }
                    if(ctn.cert[1]!=nullptr){
                        if(X509_NAME_cmp(ctn.cert[1]->cert_info->issuer,issuer)!=0){
                            fprintf(stderr,"cert1's issuer is not equal!\n");
                            continue;
                        }
                    }
                    else{
                        continue;
                    }
                    
                    strncpy(mod->validNameInfo_.mod_name,mod->name.c_str(),SKF_NAME_MAX_LENGTH);
                    mod->validNameInfo_.mod_name[SKF_NAME_MAX_LENGTH-1]='\0';

                    mod->validInfo_.devh=dev.handle;
                    strncpy(mod->validNameInfo_.dev_name,dev.name.c_str(),SKF_NAME_MAX_LENGTH);
                    mod->validNameInfo_.dev_name[SKF_NAME_MAX_LENGTH-1]='\0';
                    
                    mod->validInfo_.apph=app.handle;
                    strncpy(mod->validNameInfo_.app_name,app.name.c_str(),SKF_NAME_MAX_LENGTH);
                    mod->validNameInfo_.app_name[SKF_NAME_MAX_LENGTH-1]='\0';
                    
                    mod->validInfo_.containnerh = ctn.handle;
                    strncpy(mod->validNameInfo_.container_name,ctn.name.c_str(),SKF_NAME_MAX_LENGTH);
                    mod->validNameInfo_.container_name[SKF_NAME_MAX_LENGTH-1]='\0';
                    
                    mod->validContainer_ = &ctn;
                    *module = mod;
                    
                    return true;
                }
            }
        }
    }
    *module=nullptr;
    return false;
}


skfcontainer* skf_module_enumerator::get_container_by_issuer(X509_NAME* issuer,skfmodule** module,skf_container_info& cinfo,ukey_verify_info& uvinfo,int type)
{
    if(issuer==nullptr){
        return nullptr;
    }
    if(modules.size()==0){
        fprintf(stderr,"modules' size is zero!\n");
        return nullptr;
    }
    for(auto&it:modules){
        if(it.second==nullptr){
            continue;
        }
        skfmodule* mod=it.second;
        strncpy(uvinfo.mod_name,mod->name.c_str(),SKF_NAME_MAX_LENGTH);
        uvinfo.mod_name[SKF_NAME_MAX_LENGTH-1]='\0';
        mod->loadDevs();
        for(auto& dev:mod->devs){
            cinfo.devh=dev.handle;
            strncpy(uvinfo.dev_name,dev.name.c_str(),SKF_NAME_MAX_LENGTH);
            uvinfo.dev_name[SKF_NAME_MAX_LENGTH-1]='\0';
            for(auto&app:dev.apps){
                cinfo.apph=app.handle;
                strncpy(uvinfo.app_name,app.name.c_str(),SKF_NAME_MAX_LENGTH);
                uvinfo.app_name[SKF_NAME_MAX_LENGTH-1]='\0';
                for(auto& con:app.containers){
                    if(type == NID_sm2){
                        if(con.cert[0]==nullptr||con.cert[1]==nullptr){
                            fprintf(stderr,"cert is nullptr!\n");
                            continue;
                        }
                        if((X509_NAME_cmp(con.cert[0]->cert_info->issuer,issuer)!=0||
                        X509_NAME_cmp(con.cert[1]->cert_info->issuer,issuer))!=0){
                            fprintf(stderr,"issuer caname is not equal!\n");
                            continue;
                        }
                        EVP_PKEY* pk=X509_get_pubkey(con.cert[1]);
                        if(pk==nullptr)
                            continue;
                        if(pk->type!=type){
                            EVP_PKEY_free(pk);
                            continue;
                        }
                        EVP_PKEY_free(pk);
                        pk=X509_get_pubkey(con.cert[0]);
                        if(pk==nullptr)
                            continue;
                        if(pk->type!=type){
                            EVP_PKEY_free(pk);
                            continue;
                        }
                        EVP_PKEY_free(pk);
                    }
                    else{
                        if(con.cert[0]==nullptr){
                            fprintf(stderr,"cert is nullptr!\n");
                            continue;
                        }
                        if(X509_NAME_cmp(con.cert[0]->cert_info->issuer,issuer)!=0){
                            fprintf(stderr,"issuer caname is not equal!\n");
                            continue;
                        }
                        EVP_PKEY* pk=X509_get_pubkey(con.cert[0]);
                        if(pk==nullptr)
                            continue;
                        if(pk->type!=type){
                            EVP_PKEY_free(pk);
                            continue;
                        }
                        EVP_PKEY_free(pk);
                    }
                    *module=mod;
                    cinfo.containnerh=con.handle;
                    strncpy(uvinfo.container_name,con.name.c_str(),SKF_NAME_MAX_LENGTH);
                    uvinfo.container_name[SKF_NAME_MAX_LENGTH-1]='\0';
                    return &con;
                }
            }
        }
    }
    cinfo.reset();
    return nullptr;
}

bool skf_module_enumerator::get_load_lib_result(const std::string& file){

    void * handle=nullptr;
    handle=dlopen(file.c_str(),RTLD_NOW);
    if(handle==nullptr)
    {
        perror("dlopen:");
        return false;
    }
    SKF_VerifyPIN_type  SKF_VerifyPIN=(SKF_VerifyPIN_type)dlsym(handle,"SKF_VerifyPIN");  
    if(nullptr == SKF_VerifyPIN)  {
        return false;
    }    
    return true;
}

bool skf_module_enumerator::check_lib_valid(const std::string& file){

    void * handle=nullptr;
    handle=dlopen(file.c_str(),RTLD_NOW);
    std::cout << "dlopen after" << std::endl << std::flush;
    if(handle == nullptr)
    {
       std::cout << "handle == nullptr" << std::endl << std::flush;
        perror("dlopen:");
        return false;
    }
    SKF_VerifyPIN_type  SKF_VerifyPIN=(SKF_VerifyPIN_type)dlsym(handle,"SKF_VerifyPIN");
    if(nullptr == SKF_VerifyPIN)  {
        if (handle != nullptr) {
           std::cout << "nullptr == SKF_VerifyPIN dlclose(handle)" << std::endl << std::flush;
            dlclose(handle);
        }
        return false;
    }
    if (handle != nullptr) {
        std::cout << "dlclose(handle)" << std::endl << std::flush;
        dlclose(handle);
    }
    std::cout << "check_lib_valid return true" << std::endl << std::flush;
    return true;
}

#endif