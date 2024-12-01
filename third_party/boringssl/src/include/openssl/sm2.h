/* crypto/sm2/sm2.h */
/*
 * Written by caichenghang for the TaSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 - 2018 Beijing JN TASS Technology Co.,Ltd.  All 
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by Beijing JN TASS 
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * 4. The name "TaSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    TaSSL@tass.com.cn.
 *
 * 5. Products derived from this software may not be called "TaSSL"
 *    nor may "TaSSL" appear in their names without prior written
 *    permission of the TaSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Beijing JN TASS 
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE TASSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE TASSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes software developed by the TaSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/).
 *
 */
#ifndef OPENSSL_NO_GMTLS
#ifndef SM2_HEADER_H
#define SM2_HEADER_H

#include <stddef.h>
#include <openssl/opensslconf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/digest.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif // !OPENSSL_NO_ENGINE
#include "openssl/sm3.h"

# ifdef OPENSSL_NO_GMTLS
#  error SM2 is disabled.
# endif // OPENSSL_NO_GMTLS

#define SM2_DEFAULT_POINT_CONVERSION_FORM	POINT_CONVERSION_UNCOMPRESSED

#define SM2_MAX_ID_BITS				65535
#define SM2_MAX_ID_LENGTH			(SM2_MAX_ID_BITS/8)
#define SM2_DEFAULT_ID_GMT09			"1234567812345678"
#define SM2_DEFAULT_ID_GMSSL			"anonym@gmssl.org"
#define SM2_DEFAULT_ID				SM2_DEFAULT_ID_GMT09
#define SM2_DEFAULT_ID_LENGTH			(sizeof(SM2_DEFAULT_ID) - 1)
#define SM2_DEFAULT_ID_BITS			(SM2_DEFAULT_ID_LENGTH * 8)
#define SM2_DEFAULT_ID_DIGEST_LENGTH		SM3_DIGEST_LENGTH

struct sm2dh_data_st
{
    int server;       /*server side flag, 0 -- client side; other -- server side*/
    int checksum;     /*calculate check sum tag, 0 -- don't checksum; other  -- checksum*/
    int r_len;        /*private key length, and this is a tag for self data filled*/
    int Rp_len;       /*peer key agreement data filled tag*/
    int Rs_len;       /*self key agreement data*/
    unsigned char r[64];      /*Generated private key, MAX to 512 bits*/
    unsigned char Rs[129];    /*self public key, MAX to 512 bits + 1 tag*/
    unsigned char Rp[129];    /*peer public key, MAX to 512 bits + 1 tag*/
    unsigned char s_checksum[EVP_MAX_MD_SIZE];    /*send checksum*/
    unsigned char e_checksum[EVP_MAX_MD_SIZE];    /*ensure checksum*/
    int peerid_len;    /*ID length*/
    int selfid_len;    /*ID length*/
    unsigned char peer_id[128];    /*ID*/
    unsigned char self_id[128];    /*ID*/
};

typedef struct sm2dh_data_st SM2DH_DATA;

typedef struct SM2_enc_ctx_st
{
    uint8_t bykG04xy[128];
    uint8_t bykPbxy[128];
    char byk[128];
    uint32_t dwct;
    SM3_CTX c3sm3;
    uint8_t bybuf[32];
    int32_t ncachelen;
    EC_KEY *eckey;
    int32_t nbdecinit;
    uint8_t byC3[32];
    int nc3len;
}SM2_enc_ctx;

struct sm2enc_st
{
    ASN1_INTEGER *x;
    ASN1_INTEGER *y;
    ASN1_OCTET_STRING *m;
    ASN1_OCTET_STRING *c;
};

// typedef struct {
//     /* Key and paramgen group */
//     EC_GROUP *gen_group;
//     /* message digest */
//     const EVP_MD *md;
//     /* Duplicate key if custom cofactor needed */
//     EC_KEY *co_key;
//     /* Cofactor mode */
//     signed char cofactor_mode;
//     /* KDF (if any) to use for ECDH */
//     char kdf_type;
//     /* Message digest to use for key derivation */
//     const EVP_MD *kdf_md;
//     /* User key material */
//     unsigned char *kdf_ukm;
//     size_t kdf_ukmlen;
//     /* KDF output length */
//     size_t kdf_outlen;

//     /* server tag */
//     int server;
//     /* peer uid */
//     char *peer_id;
//     /* self uid */
//     char *self_id;
//     /* peer uid length */
//     int peerid_len;
//     /* self uid length */
//     int selfid_len;
//     /* peer ephemeral public key */
//     EC_KEY *peer_ecdhe_key;
//     /* self ephemeral key */
//     EC_KEY *self_ecdhe_key;
//     /* sm2/ecc encrypt out format, 0 for ASN1 */
//     int encdata_format;
// }EC_PKEY_CTX;

// struct evp_pkey_ctx_st {
//   // Method associated with this operation
//   const EVP_PKEY_METHOD *pmeth;
//   // Engine that implements this method or NULL if builtin
//   ENGINE *engine;
//   // Key: may be NULL
//   EVP_PKEY *pkey;
//   // Peer key for key agreement, may be NULL
//   EVP_PKEY *peerkey;
//   // operation contains one of the |EVP_PKEY_OP_*| values.
//   int operation;
//   // Algorithm specific data
//   void *data;
// } /* EVP_PKEY_CTX */;

typedef struct sm2enc_st SM2ENC;

# ifdef __cplusplus
extern "C"
{
# endif // __cplusplus
    int KDF_GMT003_2012(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, const unsigned char *SharedInfo, size_t SharedInfolen, const EVP_MD *md);
    int ECDSA_sm2_get_Z(const EC_KEY *ec_key, const EVP_MD *md, const char *uid, int uid_len, unsigned char *z_buf, size_t *z_len);


    int SM2_get_public_key_data(EC_KEY *ec_key, unsigned char *out, size_t *outlen);
    /* compute identity digest Z */
    int SM2_compute_id_digest(const EVP_MD *md, const char *id, size_t idlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
    int SM2_compute_message_digest(const EVP_MD *id_md, const EVP_MD *msg_md, const unsigned char *msg, size_t msglen, const char *id, size_t idlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
        
    
    /*SM2 Sign*/
    ECDSA_SIG *sm2_do_sign(const uint8_t *dgst, size_t dgst_len, const EC_KEY *eckey);
    ECDSA_SIG *SM2_do_sign_ex(const unsigned char *dgst, int dgstlen,
	const BIGNUM *k, const BIGNUM *x, EC_KEY *ec_key);
    int sm2_do_verify(const uint8_t *dgst, size_t dgst_len, const ECDSA_SIG *sig, const EC_KEY *eckey);

    int SM2_sign_ex(int type, const unsigned char *dgst, int dgstlen,unsigned char *sig, unsigned int *siglen,
	            const BIGNUM *k, const BIGNUM *x, EC_KEY *ec_key);
    int SM2_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
    int SM2_verify(int type, const unsigned char *dgst, int dgstlen, const unsigned char *sig, int siglen, EC_KEY *ec_key);

    int __sm2_encrypt(unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen, const EVP_MD *md, EC_KEY *ec_key);
    int __sm2_decrypt(unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen, const EVP_MD *md, EC_KEY *ec_key);

    #define SM2_encrypt_with_recommended(in,inlen,out,outlen,ec_key)    \
	    __sm2_encrypt(out,outlen,in,inlen, EVP_sm3(), ec_key)
    #define SM2_decrypt_with_recommended(in,inlen,out,outlen,ec_key)    \
	    __sm2_decrypt(out,outlen,in,inlen, EVP_sm3(), ec_key)

    int __sm2_encrypt_gmt(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen, uint8_t *pbCdata, size_t *pndatalen, int nformat);
  
    /*SM2 Encrypt And Decrypt*/
    SM2ENC *SM2ENC_new(void);
    void SM2ENC_free(SM2ENC *a);
    
    int i2d_SM2ENC(const SM2ENC *a, unsigned char **out);
    SM2ENC *d2i_SM2ENC(SM2ENC **a, const unsigned char **in, long len);

    SM2ENC *sm2_encrypt(const unsigned char *in, size_t inlen, const EVP_MD *md, EC_KEY *ec_key);
    int sm2_decrypt(unsigned char *out, size_t *outlen, const SM2ENC *in, const EVP_MD *md, EC_KEY *ec_key);

    /*SM2 Encrypt: charactor string 2 internal structure*/
    int i2c_sm2_enc(const SM2ENC *sm2enc, unsigned char **out);
    SM2ENC *c2i_sm2_enc(const unsigned char *in, size_t inlen, int md_size);

    /*EC Encrypt: charactor string 2 internal structure*/
    int i2c_ec_enc(const SM2ENC *ec_enc, int curve_name, unsigned char **out);
    SM2ENC *c2i_ec_enc(const unsigned char *in, size_t inlen, int curve_name, int md_size);

    int SM2_ENC(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen,
            uint8_t *pbCdata, size_t *pndatalen);

    int SM2_DEC(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen,
                uint8_t *pbCdata, size_t *pndatalen);

    int SM2_ENC_GMT(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen,
                    uint8_t *pbCdata, size_t *pndatalen, int nformat);
    
    // int SM2_Z(EC_KEY *key, const char *pcbid, uint32_t widlen, uint8_t *pbZ);

    /*SM2 DH*/
    int SM2DH_get_ex_data_index(void);
    int SM2DH_set_ex_data(const EC_KEY *ecKey, void *datas);
    void *SM2DH_get_ex_data(const EC_KEY *ecKey);
    int SM2DH_prepare(EC_KEY *ecKey, int server, unsigned char *R, size_t *R_len);
    int SM2DH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, const EC_KEY *eckey, void *(*KDF) (const void *in, size_t inlen, void *out, size_t *outlen));
    int SM2DH_get_ensure_checksum(void *out, EC_KEY *eckey);
    int SM2DH_get_send_checksum(void *out, EC_KEY *eckey);
    int SM2Kap_compute_key(void *out, size_t outlen, int server, \
        const char *peer_uid, int peer_uid_len, const char *self_uid, int self_uid_len, \
        const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key, const EC_KEY *peer_pub_key, const EC_KEY *self_eckey, \
        const EVP_MD *md);

    /*SM2 ERR*/
    void ERR_load_SM2_strings(void);

//     /* Function codes. */
// #  define SM2_F_SM2_GET_Z                                  100
// #  define SM2_F_SM2_PUB_ENCRYPT                            101
// #  define SM2_F_SM2_PRIV_DECRYPT                           102
// #  define SM2_F_SM2_CIPHER2TEXT                            103
// #  define SM2_F_SM2_CIPHER2STRUCTURE                       104
// #  define SM2_F_EC_CIPHER2TEXT                             105
// #  define SM2_F_EC_CIPHER2STRUCTURE                        106
// #  define SM2_F_SM2_PREPARE                              107
// #  define SM2_F_SM2_COMPUTE_KEY                          108
// #  define SM2_F_KAP_COMPUTE_KEY                           109
// #  define SM2_F_SM2_SIGN                                110
// #  define SM2_F_SM2_VERIFY                              111

    /* Reason codes. */

# ifdef __cplusplus
}
# endif // __cplusplus

#  define SM2_R_INVALID_CURVE                             100
#  define SM2_R_INVALID_ARGUMENT                          101
#  define SM2_R_INVALID_PRIVATE_KEY                       102
#  define SM2_R_INVALID_DIGEST                            103
#  define SM2_R_INVALID_CIPHER_TEXT                       104
#  define SM2_R_MISSING_PARAMETERS                        105
#  define SM2_R_SIGNATURE_MALLOC_FAILED                   106
#  define SM2_R_RANDOM_NUMBER_GENERATION_FAILED           107
#  define SM2_R_VERIFY_MALLOC_FAILED                      108
#  define SM2_R_BAD_SIGNATURE                             109
#  define SM2_R_NO_PRIVATE_VALUE                          110
#  define SM2_R_EC_GROUP_NEW_BY_NAME_FAILURE              111
#  define SM2_R_INVALID_DIGEST_ALGOR        112
#  define SM2_R_INVALID_SM2_ID              113
#  define SM2_R_INVALID_ID_LENGTH           114
#  define SM2_R_INVALID_MD                   115


#endif // !SM2_HEADER_H
#endif
