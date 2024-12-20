/* crypto/modes/wrap128.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2013 The OpenSSL Project.  All rights reserved.
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
 */

//#include "cryptlib.h"
#include "modes_old.h"

static const uint8_t default_iv[] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
};

/*
 * Input size limit: lower than maximum of standards but far larger than
 * anything that will be used in practice.
 */
#define CRYPTO128_WRAP_MAX (1UL << 31)

size_t CRYPTO_128_wrap_old(void *key, const uint8_t *iv,
                       uint8_t *out,
                       const uint8_t *in, size_t inlen,
                       block128_f_old block)
{
    uint8_t *A, B[16], *R;
    size_t i, j, t;
    if ((inlen & 0x7) || (inlen < 8) || (inlen > CRYPTO128_WRAP_MAX))
        return 0;
    A = B;
    t = 1;
    memmove(out + 8, in, inlen);
    if (!iv)
        iv = default_iv;

    memcpy(A, iv, 8);

    for (j = 0; j < 6; j++) {
        R = out + 8;
        for (i = 0; i < inlen; i += 8, t++, R += 8) {
            memcpy(B + 8, R, 8);
            block(B, B, key);
            A[7] ^= (uint8_t)(t & 0xff);
            if (t > 0xff) {
                A[6] ^= (uint8_t)((t >> 8) & 0xff);
                A[5] ^= (uint8_t)((t >> 16) & 0xff);
                A[4] ^= (uint8_t)((t >> 24) & 0xff);
            }
            memcpy(R, B + 8, 8);
        }
    }
    memcpy(out, A, 8);
    return inlen + 8;
}

size_t CRYPTO_128_unwrap_old(void *key, const uint8_t *iv,
                         uint8_t *out,
                         const uint8_t *in, size_t inlen,
                         block128_f_old block)
{
    uint8_t *A, B[16], *R;
    size_t i, j, t;
    inlen -= 8;
    if ((inlen & 0x7) || (inlen < 16) || (inlen > CRYPTO128_WRAP_MAX))
        return 0;
    A = B;
    t = 6 * (inlen >> 3);
    memcpy(A, in, 8);
    memmove(out, in + 8, inlen);
    for (j = 0; j < 6; j++) {
        R = out + inlen - 8;
        for (i = 0; i < inlen; i += 8, t--, R -= 8) {
            A[7] ^= (uint8_t)(t & 0xff);
            if (t > 0xff) {
                A[6] ^= (uint8_t)((t >> 8) & 0xff);
                A[5] ^= (uint8_t)((t >> 16) & 0xff);
                A[4] ^= (uint8_t)((t >> 24) & 0xff);
            }
            memcpy(B + 8, R, 8);
            block(B, B, key);
            memcpy(R, B + 8, 8);
        }
    }
    if (!iv)
        iv = default_iv;
    if (memcmp(A, iv, 8)) {
        OPENSSL_cleanse(out, inlen);
        return 0;
    }
    return inlen;
}
