/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
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
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/evp.h>

#include <string.h>

#include <openssl/bn.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
// GMTLS
#ifndef OPENSSL_NO_GMTLS
#include <openssl/sm2.h>
#include "openssl/base.h"
#endif
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include "internal.h"
#include "../fipsmodule/ec/internal.h"
#include "../internal.h"


static int pkey_ec_init(EVP_PKEY_CTX *ctx) {
  EC_PKEY_CTX *dctx;
  dctx = OPENSSL_malloc(sizeof(EC_PKEY_CTX));
  if (!dctx) {
    return 0;
  }
  OPENSSL_memset(dctx, 0, sizeof(EC_PKEY_CTX));

  ctx->data = dctx;

  return 1;
}

static int pkey_ec_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) {
  EC_PKEY_CTX *dctx, *sctx;
  if (!pkey_ec_init(dst)) {
    return 0;
  }
  sctx = src->data;
  dctx = dst->data;

  dctx->md = sctx->md;

  return 1;
}

static void pkey_ec_cleanup(EVP_PKEY_CTX *ctx) {
  EC_PKEY_CTX *dctx = ctx->data;
  if (!dctx) {
    return;
  }

  EC_GROUP_free(dctx->gen_group);
  OPENSSL_free(dctx);
}

static int pkey_ec_sign(EVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen,
                        const uint8_t *tbs, size_t tbslen) {
  unsigned int sltmp;
  EC_KEY *ec = ctx->pkey->pkey.ec;

  if (!sig) {
    *siglen = ECDSA_size(ec);
    return 1;
  } else if (*siglen < (size_t)ECDSA_size(ec)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (!ECDSA_sign(0, tbs, tbslen, sig, &sltmp, ec)) {
    return 0;
  }
  *siglen = (size_t)sltmp;
  return 1;
}

static int pkey_ec_verify(EVP_PKEY_CTX *ctx, const uint8_t *sig, size_t siglen,
                          const uint8_t *tbs, size_t tbslen) {
  return ECDSA_verify(0, tbs, tbslen, sig, siglen, ctx->pkey->pkey.ec);
}

// GMTLS
#ifndef OPENSSL_NO_GMTLS

#ifdef UT_DEBUG
static size_t ec_key_simple_priv2oct(EC_KEY *eckey,
                                unsigned char *buf, size_t len)
{
    size_t buf_len;

    buf_len = (EC_GROUP_order_bits(eckey->group) + 7) / 8;
    if (eckey->priv_key == NULL)
        return 0;

// #ifndef OPENSSL_NO_CNSM                     //add by gujq on 20190830 for tasshsm engine v0.6
//     if(EC_KEY_get_flags((EC_KEY*)eckey) & EC_FLAG_TASSHSM_ENGINE){
// 	    	char *lmk_pri  = BN_bn2hex(EC_KEY_get0_private_key(eckey));
// 		buf_len = buf_len>strlen(lmk_pri)/2? buf_len: strlen(lmk_pri)/2;
// 		OPENSSL_free(lmk_pri);    //add by gujq on 20200113 bugfix
//     }
// #endif

    if (buf == NULL)
        return buf_len;
    else if (len < buf_len)
        return 0;


    /* Octetstring may need leading zeros if BN is to short */
    if (BN_bn2binpad( &(eckey->priv_key->bignum), buf, buf_len) == -1) {
        OPENSSL_PUT_ERROR(EVP, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    return buf_len;
}
#endif

/*this function only used to SM2Kap*/
static int pkey_ec_sm2dh_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
    size_t *keylen)
{
    int ret;
    size_t outlen;
    EC_PKEY_CTX *dctx = ctx->data;

    if (!ctx->pkey || !ctx->peerkey)
    {
        OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);
        return 0;
    }

    if (!key || (*keylen == 0))
    {
        OPENSSL_PUT_ERROR(EVP, EC_R_MISSING_PARAMETERS);
        return 0;
    }

    outlen = *keylen;

#ifdef UT_DEBUG
    unsigned char *self_pub = NULL;
    unsigned char self_priv[64] = {0};
    unsigned char *self_tmp_pub = NULL;
    unsigned char self_tmp_priv[64] = {0};
    unsigned char *peer_pub = NULL;
    unsigned char *peer_tmp_pub = NULL;
    size_t i = 0;
    
    printf("self_priv:");
    ec_key_simple_priv2oct(ctx->pkey->pkey.ec, self_priv, 64);
    for(i=0; i<32; i++){
    	printf("%02X", *(self_priv+i));
    }
    printf("\n");
    
    printf("self_pub:");
    EC_KEY_key2buf(ctx->pkey->pkey.ec, EC_KEY_get_conv_form(ctx->pkey->pkey.ec), &self_pub, NULL);
    for(i=0; i<65; i++){
    	printf("%02X", *(self_pub+i));
    }
    printf("\n");
    
    printf("self_tmp_priv:");
    ec_key_simple_priv2oct(dctx->self_ecdhe_key, self_tmp_priv, 64);
    for(i=0; i<32; i++){
    	printf("%02X", *(self_tmp_priv+i));
    }
    printf("\n");
    
    printf("self_tmp_pub:");
    EC_KEY_key2buf(dctx->self_ecdhe_key, EC_KEY_get_conv_form(dctx->self_ecdhe_key), &self_tmp_pub, NULL);
    for(i=0; i<65; i++){
    	printf("%02X", *(self_tmp_pub+i));
    }
    printf("\n");
    
    printf("peer_pub:");
    EC_KEY_key2buf(ctx->peerkey->pkey.ec, EC_KEY_get_conv_form(ctx->peerkey->pkey.ec), &peer_pub, NULL);
    for(i=0; i<65; i++){
    	printf("%02X", *(peer_pub+i));
    }
    printf("\n");
    
    printf("peer_tmp_pub:");
    EC_KEY_key2buf(dctx->peer_ecdhe_key, EC_KEY_get_conv_form(dctx->peer_ecdhe_key), &peer_tmp_pub, NULL);
    for(i=0; i<65; i++){
    	printf("%02X", *(peer_tmp_pub+i));
    }
    printf("\n");
    
#endif
    ret = SM2Kap_compute_key(key, outlen, dctx->server, dctx->peer_id, dctx->peerid_len, dctx->self_id, dctx->selfid_len, \
        dctx->peer_ecdhe_key, dctx->self_ecdhe_key, ctx->peerkey->pkey.ec, ctx->pkey->pkey.ec, dctx->kdf_md);

#ifdef UT_DEBUG
    printf("exchange key:");
    for(i=0; i<outlen; i++){
    	printf("%02X", *(key+i));
    }
    printf("\n");
#endif

    if (ret <= 0)
        return 0;
    return 1;
}
#endif

static int pkey_ec_derive(EVP_PKEY_CTX *ctx, uint8_t *key,
                          size_t *keylen) {
  int ret;
  size_t outlen;
  const EC_POINT *pubkey = NULL;
  EC_KEY *eckey;

  if (!ctx->pkey || !ctx->peerkey) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_KEYS_NOT_SET);
    return 0;
  }

#ifndef OPENSSL_NO_GMTLS
    if (EC_GROUP_get_curve_name(EC_KEY_get0_group(ctx->pkey->pkey.ec)) == NID_sm2)
    {
        /*to SM2DH or SM2KAP*/
        return pkey_ec_sm2dh_derive(ctx, key, keylen);
    }
#endif

  eckey = ctx->pkey->pkey.ec;

  if (!key) {
    const EC_GROUP *group;
    group = EC_KEY_get0_group(eckey);
    *keylen = (EC_GROUP_get_degree(group) + 7) / 8;
    return 1;
  }
  pubkey = EC_KEY_get0_public_key(ctx->peerkey->pkey.ec);

  // NB: unlike PKCS#3 DH, if *outlen is less than maximum size this is
  // not an error, the result is truncated.

  outlen = *keylen;

  ret = ECDH_compute_key(key, outlen, pubkey, eckey, 0);
  if (ret < 0) {
    return 0;
  }
  *keylen = ret;
  return 1;
}

static int pkey_ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  EC_PKEY_CTX *dctx = ctx->data;

  switch (type) {
    case EVP_PKEY_CTRL_MD:
      if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_ecdsa_with_SHA1 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_sha512 
		  // GMTLS
#ifndef OPENSSL_NO_GMTLS
          &&EVP_MD_type((const EVP_MD *)p2) != NID_sm3
#endif
		  ) {
        OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_DIGEST_TYPE);
        return 0;
      }
      dctx->md = p2;
      return 1;

    case EVP_PKEY_CTRL_GET_MD:
      *(const EVP_MD **)p2 = dctx->md;
      return 1;

    case EVP_PKEY_CTRL_PEER_KEY:
      // Default behaviour is OK
      return 1;

    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID: {
      EC_GROUP *group = EC_GROUP_new_by_curve_name(p1);
      if (group == NULL) {
        return 0;
      }
      EC_GROUP_free(dctx->gen_group);
      dctx->gen_group = group;
      return 1;
    }

    default:
      OPENSSL_PUT_ERROR(EVP, EVP_R_COMMAND_NOT_SUPPORTED);
      return 0;
  }
}

static int pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  EC_PKEY_CTX *dctx = ctx->data;
  const EC_GROUP *group = dctx->gen_group;
  if (group == NULL) {
    if (ctx->pkey == NULL) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_NO_PARAMETERS_SET);
      return 0;
    }
    group = EC_KEY_get0_group(ctx->pkey->pkey.ec);
  }
  EC_KEY *ec = EC_KEY_new();
  if (ec == NULL ||
      !EC_KEY_set_group(ec, group) ||
      !EC_KEY_generate_key(ec)) {
    EC_KEY_free(ec);
    return 0;
  }
  EVP_PKEY_assign_EC_KEY(pkey, ec);
  return 1;
}

static int pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  EC_PKEY_CTX *dctx = ctx->data;
  if (dctx->gen_group == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NO_PARAMETERS_SET);
    return 0;
  }
  EC_KEY *ec = EC_KEY_new();
  if (ec == NULL ||
      !EC_KEY_set_group(ec, dctx->gen_group)) {
    EC_KEY_free(ec);
    return 0;
  }
  EVP_PKEY_assign_EC_KEY(pkey, ec);
  return 1;
}

const EVP_PKEY_METHOD ec_pkey_meth = {
    EVP_PKEY_EC,
    pkey_ec_init,
    pkey_ec_copy,
    pkey_ec_cleanup,
    pkey_ec_keygen,
    pkey_ec_sign,
    NULL /* sign_message */,
    pkey_ec_verify,
    NULL /* verify_message */,
    NULL /* verify_recover */,
    NULL /* encrypt */,
    NULL /* decrypt */,
    pkey_ec_derive,
    pkey_ec_paramgen,
    pkey_ec_ctrl,
};

int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid) {
  return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, EVP_PKEY_OP_TYPE_GEN,
                           EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, NULL);
}

int EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int encoding) {
  // BoringSSL only supports named curve syntax.
  if (encoding != OPENSSL_EC_NAMED_CURVE) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_PARAMETERS);
    return 0;
  }
  return 1;
}

// GMTLS
#ifndef OPENSSL_NO_GMTLS
static int pkey_sm2_sign(EVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen,
                            const uint8_t *tbs, size_t tbslen) {
  unsigned int sltmp;
  EC_KEY *ec = ctx->pkey->pkey.ec;

  if (!sig) {
    *siglen = ECDSA_size(ec);
    return 1;
  } else if (*siglen < (size_t)ECDSA_size(ec)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (!SM2_sign(0, tbs, tbslen, sig, &sltmp, ec)) {
    return 0;
  }
  *siglen = (size_t)sltmp;
  return 1;
}

static int pkey_sm2_verify(EVP_PKEY_CTX *ctx, const uint8_t *sig,
                              size_t siglen, const uint8_t *tbs,
                              size_t tbslen) {
  return SM2_verify(0, tbs, tbslen, sig, siglen, ctx->pkey->pkey.ec);
}

static int pkey_sm2_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  EC_PKEY_CTX *dctx = ctx->data;

  if (ctx->pkey == NULL && dctx->gen_group == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NO_PARAMETERS_SET);
    return 0;
  }
  EC_KEY *ec = EC_KEY_new();
  if (ec == NULL)
  {
    return 0;
  }

  if( ctx->pkey == NULL)
  {
      if( !EC_KEY_set_group(ec, dctx->gen_group))
      {
          EC_KEY_free(ec);
          return 0;
      }
  }
  else
  { 
      if( !EC_KEY_set_group(ec, EC_KEY_get0_group(ctx->pkey->pkey.ec)))
      {
          EC_KEY_free(ec);
          return 0;
      }
  }

  if( !EC_KEY_generate_key(ec))
  {
    EC_KEY_free(ec);
    return 0;
  }  

  EVP_PKEY_assign_SM2_KEY(pkey, ec);
  return 1;
}

static int pkey_sm2_encrypt(EVP_PKEY_CTX *ctx, uint8_t *out, size_t *outlen,
                            const uint8_t *in, size_t inlen) {
  // EC_PKEY_CTX *dctx = ctx->data;
  EC_KEY *ec = ctx->pkey->pkey.ec;

  if (!ec) {
    return 0;
  }
  return SM2_encrypt_with_recommended( in, inlen, out, outlen, ec);
}

static int pkey_sm2_decrypt(EVP_PKEY_CTX *ctx, uint8_t *out, size_t *outlen,
                            const uint8_t *in, size_t inlen) {
  // EC_PKEY_CTX *dctx = ctx->data;
  EC_KEY *ec = ctx->pkey->pkey.ec;

  if (!ec) {
    return 0;
  }
  return SM2_decrypt_with_recommended(in, inlen, out, outlen, ec);
}

static int pkey_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  EC_PKEY_CTX *dctx = ctx->data;
  EC_GROUP *group;

  switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            OPENSSL_PUT_ERROR(EVP, SM2_R_INVALID_CURVE);
            return 0;
        }
        EC_GROUP_free(dctx->gen_group);
        dctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_MD:
      if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_ecdsa_with_SHA1 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_sha512 &&
          EVP_MD_type((const EVP_MD *)p2) != NID_sm3) {
        OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_DIGEST_TYPE);
        return 0;
      }
      dctx->md = p2;
      return 1;

    case EVP_PKEY_CTRL_GET_MD:
      *(const EVP_MD **)p2 = dctx->md;
      return 1;

    case EVP_PKEY_CTRL_PEER_KEY:
      /* Default behaviour is OK */
      return 1;

    default:
      OPENSSL_PUT_ERROR(EVP, EVP_R_COMMAND_NOT_SUPPORTED);
      return 0;
  }
}


const EVP_PKEY_METHOD ec_sm2_pkey_meth = {
    EVP_PKEY_SM2,
    pkey_ec_init,
    pkey_ec_copy,
    pkey_ec_cleanup,
    pkey_sm2_keygen,
    pkey_sm2_sign,
    NULL /* sign_message */,
    pkey_sm2_verify,
    NULL /* verify_message */,
    NULL /* verify_recover */,
    pkey_sm2_encrypt,
    pkey_sm2_decrypt,
    pkey_ec_derive,
    pkey_ec_paramgen,
    pkey_sm2_ctrl,
};

int EVP_PKEY_CTX_set_sm2_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid) {
  return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, EVP_PKEY_OP_TYPE_GEN,
                           EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, NULL);
}

int EVP_PKEY_CTX_set_sm2_param_enc(EVP_PKEY_CTX *ctx, int encoding) {
  // BoringSSL only supports named curve syntax.
  if (encoding != OPENSSL_EC_NAMED_CURVE) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_PARAMETERS);
    return 0;
  }
  return 1;
}

void * EVP_PKEY_CTX_get_data(EVP_PKEY_CTX *ctx)
{
  return ctx->data;
}


#endif