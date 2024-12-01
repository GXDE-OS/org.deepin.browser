/* crypto/evp/m_sm3.c */
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

#include <stdio.h>
//#include "cryptlib.h"

#ifndef OPENSSL_NO_GMTLS

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/sm3.h>
#include "../fipsmodule/digest/internal.h"
//# include "evp_locl.h"

static void init(EVP_MD_CTX *ctx)
{
    SM3_Init(ctx->md_data);
}

#ifdef UT_DEBUG
static void myPrintData(const void *data, size_t count)
{
    for(size_t i = 0; i < count; ++i)
    {
        printf("%o", *((uint8_t*)data+i));
    }
}
#endif

static void update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
#ifdef UT_DEBUG
    printf("SM3_Update %p , count %lu : ", ctx, count);
    myPrintData(data, count);
    printf("\n");
#endif
    SM3_Update(ctx->md_data, data, count);
}

static void final(EVP_MD_CTX *ctx, uint8_t *md)
{
    SM3_Final(md, ctx->md_data);
}

EVP_MD sm3_md = {
    NID_sm3,
    SM3_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    SM3_CBLOCK,   
    sizeof(SM3_CTX)
};

const EVP_MD *EVP_sm3(void)
{
    return (&sm3_md);
}

int is_ec_pkey_type(int a, int b)
{
  if(a != EVP_PKEY_SM2 && a != EVP_PKEY_EC)
  {
      return 0;
  }

  if(b != EVP_PKEY_SM2 && b != EVP_PKEY_EC)
  {
      return 0;
  }

  return 1;
}

#endif

