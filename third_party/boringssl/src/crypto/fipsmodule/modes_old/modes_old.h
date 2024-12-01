/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project. All rights reserved.
 *
 * Rights for redistribution and usage in source and binary
 * forms are granted according to the OpenSSL license.
 */

#include <stddef.h>
#include "openssl/base.h"

#ifdef  __cplusplus
extern "C" {
#endif
typedef void (*block128_f_old) (const uint8_t in[16],
                            uint8_t out[16], const void *key);

typedef void (*cbc128_f_old) (const uint8_t *in, uint8_t *out,
                          size_t len, const void *key,
                          uint8_t ivec[16], int enc);

typedef void (*ctr128_f_old) (const uint8_t *in, uint8_t *out,
                          size_t blocks, const void *key,
                          const uint8_t ivec[16]);

typedef void (*ccm128_f_old) (const uint8_t *in, uint8_t *out,
                          size_t blocks, const void *key,
                          const uint8_t ivec[16],
                          uint8_t cmac[16]);

void CRYPTO_cbc128_encrypt_old(const uint8_t *in, uint8_t *out,
                           size_t len, const void *key,
                           uint8_t ivec[16], block128_f_old block);
void CRYPTO_cbc128_decrypt_old(const uint8_t *in, uint8_t *out,
                           size_t len, const void *key,
                           uint8_t ivec[16], block128_f_old block);

void CRYPTO_ctr128_encrypt_old(const uint8_t *in, uint8_t *out,
                           size_t len, const void *key,
                           uint8_t ivec[16],
                           uint8_t ecount_buf[16], unsigned int *num,
                           block128_f_old block);

void CRYPTO_ctr128_encrypt_ctr32_old(const uint8_t *in, uint8_t *out,
                                 size_t len, const void *key,
                                 uint8_t ivec[16],
                                 uint8_t ecount_buf[16],
                                 unsigned int *num, ctr128_f_old ctr);

void CRYPTO_ofb128_encrypt_old(const uint8_t *in, uint8_t *out,
                           size_t len, const void *key,
                           uint8_t ivec[16], unsigned *num,
                           block128_f_old block);

void CRYPTO_cfb128_encrypt_old(const uint8_t *in, uint8_t *out,
                           size_t len, const void *key,
                           uint8_t ivec[16], unsigned *num,
                           int enc, block128_f_old block);
void CRYPTO_cfb128_8_encrypt_old(const uint8_t *in, uint8_t *out,
                             size_t length, const void *key,
                             uint8_t ivec[16], int *num,
                             int enc, block128_f_old block);
void CRYPTO_cfb128_1_encrypt_old(const uint8_t *in, uint8_t *out,
                             size_t bits, const void *key,
                             uint8_t ivec[16], int *num,
                             int enc, block128_f_old block);

size_t CRYPTO_cts128_encrypt_block_old(const uint8_t *in,
                                   uint8_t *out, size_t len,
                                   const void *key, uint8_t ivec[16],
                                   block128_f_old block);
size_t CRYPTO_cts128_encrypt_old(const uint8_t *in, uint8_t *out,
                             size_t len, const void *key,
                             uint8_t ivec[16], cbc128_f_old cbc);
size_t CRYPTO_cts128_decrypt_block_old(const uint8_t *in,
                                   uint8_t *out, size_t len,
                                   const void *key, uint8_t ivec[16],
                                   block128_f_old block);
size_t CRYPTO_cts128_decrypt_old(const uint8_t *in, uint8_t *out,
                             size_t len, const void *key,
                             uint8_t ivec[16], cbc128_f_old cbc);

size_t CRYPTO_nistcts128_encrypt_block_old(const uint8_t *in,
                                       uint8_t *out, size_t len,
                                       const void *key,
                                       uint8_t ivec[16],
                                       block128_f_old block);
size_t CRYPTO_nistcts128_encrypt_old(const uint8_t *in, uint8_t *out,
                                 size_t len, const void *key,
                                 uint8_t ivec[16], cbc128_f_old cbc);
size_t CRYPTO_nistcts128_decrypt_block_old(const uint8_t *in,
                                       uint8_t *out, size_t len,
                                       const void *key,
                                       uint8_t ivec[16],
                                       block128_f_old block);
size_t CRYPTO_nistcts128_decrypt_old(const uint8_t *in, uint8_t *out,
                                 size_t len, const void *key,
                                 uint8_t ivec[16], cbc128_f_old cbc);

typedef struct gcm128_context GCM128_CONTEXT_OLD;

GCM128_CONTEXT_OLD *CRYPTO_gcm128_new_old(void *key, block128_f_old block);
void CRYPTO_gcm128_init_old(GCM128_CONTEXT_OLD *ctx, void *key, block128_f_old block);
void CRYPTO_gcm128_setiv_old(GCM128_CONTEXT_OLD *ctx, const uint8_t *iv,
                         size_t len);
int CRYPTO_gcm128_aad_old(GCM128_CONTEXT_OLD *ctx, const uint8_t *aad,
                      size_t len);
int CRYPTO_gcm128_encrypt_old(GCM128_CONTEXT_OLD *ctx,
                          const uint8_t *in, uint8_t *out,
                          size_t len);
int CRYPTO_gcm128_decrypt_old(GCM128_CONTEXT_OLD *ctx,
                          const uint8_t *in, uint8_t *out,
                          size_t len);
int CRYPTO_gcm128_encrypt_ctr32_old(GCM128_CONTEXT_OLD *ctx,
                                const uint8_t *in, uint8_t *out,
                                size_t len, ctr128_f_old stream);
int CRYPTO_gcm128_decrypt_ctr32_old(GCM128_CONTEXT_OLD *ctx,
                                const uint8_t *in, uint8_t *out,
                                size_t len, ctr128_f_old stream);
int CRYPTO_gcm128_finish_old(GCM128_CONTEXT_OLD *ctx, const uint8_t *tag,
                         size_t len);
void CRYPTO_gcm128_tag_old(GCM128_CONTEXT_OLD *ctx, uint8_t *tag, size_t len);
void CRYPTO_gcm128_release_old(GCM128_CONTEXT_OLD *ctx);

typedef struct ccm128_context CCM128_CONTEXT;

void CRYPTO_ccm128_init_old(CCM128_CONTEXT *ctx,
                        unsigned int M, unsigned int L, void *key,
                        block128_f_old block);
int CRYPTO_ccm128_setiv_old(CCM128_CONTEXT *ctx, const uint8_t *nonce,
                        size_t nlen, size_t mlen);
void CRYPTO_ccm128_aad_old(CCM128_CONTEXT *ctx, const uint8_t *aad,
                       size_t alen);
int CRYPTO_ccm128_encrypt_old(CCM128_CONTEXT *ctx, const uint8_t *inp,
                          uint8_t *out, size_t len);
int CRYPTO_ccm128_decrypt_old(CCM128_CONTEXT *ctx, const uint8_t *inp,
                          uint8_t *out, size_t len);
int CRYPTO_ccm128_encrypt_ccm64_old(CCM128_CONTEXT *ctx, const uint8_t *inp,
                                uint8_t *out, size_t len,
                                ccm128_f_old stream);
int CRYPTO_ccm128_decrypt_ccm64_old(CCM128_CONTEXT *ctx, const uint8_t *inp,
                                uint8_t *out, size_t len,
                                ccm128_f_old stream);
size_t CRYPTO_ccm128_tag_old(CCM128_CONTEXT *ctx, uint8_t *tag, size_t len);

typedef struct xts128_context XTS128_CONTEXT;

int CRYPTO_xts128_encrypt_old(const XTS128_CONTEXT *ctx,
                          const uint8_t iv[16],
                          const uint8_t *inp, uint8_t *out,
                          size_t len, int enc);

size_t CRYPTO_128_wrap_old(void *key, const uint8_t *iv,
                       uint8_t *out,
                       const uint8_t *in, size_t inlen,
                       block128_f_old block);

size_t CRYPTO_128_unwrap_old(void *key, const uint8_t *iv,
                         uint8_t *out,
                         const uint8_t *in, size_t inlen,
                         block128_f_old block);

#ifdef  __cplusplus
}
#endif
