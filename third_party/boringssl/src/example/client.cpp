//#include "openssl/bio.h"  
#include "openssl/ssl.h"  
#include "openssl/err.h" 
 
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <string>
 
#define SERVER_PORT 4433
#define SERVER_IP "127.0.0.1"
 
#define CA_CERT_FILE            "gm_cert/certs/CA.crt"
#define CLIENT_CERT_FILE        "gm_cert/certs/CS.crt"
#define CLIENT_KEY_FILE         "gm_cert/certs/CS.key"
#define CLIENT_ENCODE_CERT_FILE "gm_cert/certs/CE.crt"
#define CLIENT_ENCODE_KEY_FILE  "gm_cert/certs/CE.key"
 
int main(int argc, char **argv)  
{  
    std::string address = SERVER_IP;

    printf("Client Running in LINUX\n");
 
    if(argc > 1)
    {
        address = argv[1];
    }
 
    SSL_CTX     *ctx;  
    SSL         *ssl;  
 
    int nFd;  
    int nLen;  
    char szBuffer[1024];  
    
    SSL_library_init();
 
    // 使用GMTLS 
    ctx = SSL_CTX_new (TLS_client_method());
    //ctx = SSL_CTX_new (TLSv1_2_client_method());
    if( ctx == NULL)
    {
        printf("SSL_CTX_new error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
 
    // 要求校验对方证书，表示需要验证服务器端，若不需要验证则使用  SSL_VERIFY_NONE
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  
 
    // 加载CA的证书
    printf("SSL_CTX_load_verify_locations start!\n");
    if(!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL))
    {
        printf("SSL_CTX_load_verify_locations error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
 
    // 加载自己的证书  
    if(SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_certificate_file error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
 
    //加载自己的私钥 加载私钥需要密码，意思是每次链接服务器都需要密码
    //若服务器需要验证客户端的身份，则需要客户端加载私钥，由于此处我们只需要验证服务器身份，故无需加载自己的私钥
    printf("SSL_CTX_use_PrivateKey_file start!\n");
    if(SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
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
    // 加载自己的证书 
    if(SSL_CTX_use_enc_certificate_file(ctx, CLIENT_ENCODE_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_enc_certificate_file 2 error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    //加载自己的私钥 加载私钥需要密码，意思是每次链接服务器都需要密码
    //若服务器需要验证客户端的身份，则需要客户端加载私钥，由于此处我们只需要验证服务器身份，故无需加载自己的私钥
    printf("SSL_CTX_use_enc_PrivateKey_file 2 start!\n");
    if(SSL_CTX_use_enc_PrivateKey_file(ctx, CLIENT_ENCODE_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_enc_PrivateKey_file 2 error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
 
    //判定私钥是否正确  
    if(!SSL_CTX_check_enc_private_key(ctx))
    {
        printf("SSL_CTX_check_enc_private_key error!\n");
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
 
    // 创建连接  
    nFd = ::socket(AF_INET, SOCK_STREAM, 0); 
 
    struct sockaddr_in addr; 
    addr.sin_addr.s_addr = inet_addr(address.c_str());
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
 
    //链接服务器 
    if(connect(nFd, (sockaddr *)&addr, sizeof(addr)) < 0)  
    {  
        printf("connect\n"); 
        ERR_print_errors_fp(stderr);
        return -1;  
    }  
 
    // 将连接付给SSL  
    ssl = SSL_new (ctx);
    if( ssl == NULL)
    {
        printf("SSL_new error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

	
	//if( SSL_set_cipher_list(ssl, "GMTLS_SM2_WITH_SM4_SM3") != 1)
	if( SSL_set_cipher_list(ssl, "GMTLS_SM2DHE_WITH_SM4_SM3") != 1)
    {
        printf("SSL_set_cipher_list faied!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_set_fd (ssl, nFd);  
    if( SSL_connect (ssl) != 1)
    {
        printf("SSL_new error!\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
 
    // 进行操作  
    sprintf(szBuffer, "\nthis is from client+++++++++++++++client send to server");  
    SSL_write(ssl, szBuffer, strlen(szBuffer));
 
    // 释放资源  
    memset(szBuffer, 0, sizeof(szBuffer));  
    nLen = SSL_read(ssl,szBuffer, sizeof(szBuffer));  
    fprintf(stderr, "Get Len %d %s ok\n", nLen, szBuffer);  
 
    SSL_free (ssl);  
    SSL_CTX_free (ctx);  
    close(nFd);     
} 