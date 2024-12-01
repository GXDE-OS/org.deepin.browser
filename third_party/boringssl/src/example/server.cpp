#include "openssl/bio.h"  
#include "openssl/ssl.h"  
#include "openssl/err.h" 
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
 
#define SERVER_PORT 19968
// #define CA_CERT_FILE 		"gm_cert/ca.crt"
// #define SIGN_CERT_FILE 		"gm_cert/server.crt"
// #define SIGN_KEY_FILE 		"gm_cert/server.key"
// #define ENCODE_CERT_FILE 	"gm_cert/server1.crt"
// #define ENCODE_KEY_FILE 	"gm_cert/server1.key"
 

#define CA_CERT_FILE 		"gm_cert/certs/CA.crt"
#define SIGN_CERT_FILE 		"gm_cert/certs/SS.crt"
#define SIGN_KEY_FILE 		"gm_cert/certs/SS.key"
#define ENCODE_CERT_FILE 	"gm_cert/certs/SE.crt"
#define ENCODE_KEY_FILE 	"gm_cert/certs/SE.key"

// #define CA_CERT_FILE 		"gm_cert/gmcert20200927/Test.cert.pem"
// #define SIGN_CERT_FILE 		"gm_cert/gmcert20200927/Test.cert.pem"
// #define SIGN_KEY_FILE 		"gm_cert/gmcert20200927/Test.key.pem"
// #define ENCODE_CERT_FILE 	"gm_cert/certs/SE.crt"
// #define ENCODE_KEY_FILE 	"gm_cert/certs/SE.key"



typedef struct sockaddr SA;
static int TcpInit()
{
    int listener;
    do{
        listener = ::socket(AF_INET, SOCK_STREAM, 0);
        if( listener == -1 )
            return false;
 
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = 0;
        sin.sin_port = htons(SERVER_PORT);
 
        if( ::bind(listener, (SA*)&sin, sizeof(sin)) < 0 )
            break;
 
        if( ::listen(listener, 5) < 0)
            break;
 
        return listener;
    }while(0);
 
    return -1;
}
 
int main(int argc, char **argv)  
{  
    printf("Server Running in LINUX\n");
 
    SSL_CTX     *ctx;  
    SSL         *ssl;  
    //X509        *client_cert;  
    char szBuffer[1024];  
    int nLen;  
    struct sockaddr_in addr;   
    int nListenFd, nAcceptFd;  
 
    nListenFd = TcpInit();
    SSL_library_init();
    SSLeay_add_ssl_algorithms();  
    OpenSSL_add_all_algorithms();  
    SSL_load_error_strings();  

    ERR_load_BIO_strings();  
 
    memset(&addr, 0, sizeof(addr));

    socklen_t len  = sizeof(addr);
   
    //int iMode = 1;
    //int iret = ioctlsocket(nAcceptFd, FIONBIO, (u_long FAR*)&iMode); 
    ctx = SSL_CTX_new (TLS_server_method());
    //ctx = SSL_CTX_new (TLSv1_2_server_method());
    if( ctx == NULL)
    {
        printf("SSL_CTX_new error!\n");
        return -1;
    }
 
    // 是否要求校验对方证书 此处不验证客户端身份所以为： SSL_VERIFY_NONE
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  
 
    // 加载CA的证书  
    if(!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL))
    {
        printf("SSL_CTX_load_verify_locations error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
 
    // 加载自己的证书  
    if(SSL_CTX_use_certificate_file(ctx, SIGN_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_certificate_file error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
 
    // 加载自己的私钥  私钥的作用是，ssl握手过程中，对客户端发送过来的随机
    //消息进行加密，然后客户端再使用服务器的公钥进行解密，若解密后的原始消息跟
    //客户端发送的消息一直，则认为此服务器是客户端想要链接的服务器
    if(SSL_CTX_use_PrivateKey_file(ctx, SIGN_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_PrivateKey_file error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 判定私钥是否正确  
    if(!SSL_CTX_check_private_key(ctx))
    {
        printf("SSL_CTX_check_private_key error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

// GMTLS
#ifndef OPENSSL_NO_GMTLS	
    if(SSL_CTX_use_enc_certificate_file(ctx, ENCODE_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_enc_certificate_file 1 error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if(SSL_CTX_use_enc_PrivateKey_file(ctx, ENCODE_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_enc_PrivateKey_file 1 error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    // 判定私钥是否正确  
    if(!SSL_CTX_check_enc_private_key(ctx))
    {
        printf("SSL_CTX_check_enc_private_key 1 error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (!SSL_CTX_set_max_proto_version(ctx, GMTLS_VERSION)) 
    {
        printf("SSL_CTX_set_max_proto_version GMTLS_VERSION error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
#endif
    while(1)
    {
        nAcceptFd = accept(nListenFd, (struct sockaddr *)&addr, &len);
        if(nAcceptFd==-1)
        {
            perror("accept");
            exit(errno);
        }
        // 将连接付给SSL  
        ssl = SSL_new (ctx);
        if(!ssl)
        {
            printf("SSL_new error!\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }
        int res =SSL_set_fd (ssl, nAcceptFd); 
        printf("SSL_set_fd res %d \n", res);
        
        if(SSL_accept (ssl) != 1)
        {
            int icode = -1;
            ERR_print_errors_fp(stderr);
            int iret = SSL_get_error(ssl, icode);
            printf("SSL_accept error! code = %d, iret = %d\n", icode, iret);
        }
        else
        {
            break;
        }
    }
 
    // 进行操作  
    memset(szBuffer, 0, sizeof(szBuffer));  
    nLen = SSL_read(ssl,szBuffer, sizeof(szBuffer));  
    fprintf(stderr, "Get Len %d %s ok\n", nLen, szBuffer);  
    strcat(szBuffer, "\n this is from server========server resend to client");  
    SSL_write(ssl, szBuffer, strlen(szBuffer));  
 
    // 释放资源  
    SSL_free (ssl);  
    SSL_CTX_free (ctx);  
    close(nAcceptFd);  
}  