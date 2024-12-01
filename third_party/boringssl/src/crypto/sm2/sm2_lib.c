/* crypto/sm2/sm2_lib.c */
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

#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
//#include <openssl/base.h>
#include <openssl/objects.h>
#include <openssl/asn1t.h>
#include <string.h>
#include "../fipsmodule/digest/internal.h"
#include <openssl/mem.h>
#include "../internal.h"
#include <limits.h>
#include <openssl/rand.h>

//const char SM2_version[] = "SM2" OPENSSL_VERSION_PTEXT;
const char SM2_version[] = "SM2";

# ifndef OPENSSL_ECC_MAX_FIELD_BITS
#  define OPENSSL_ECC_MAX_FIELD_BITS 661
# endif

#define EC_MAX_NBYTES  ((OPENSSL_ECC_MAX_FIELD_BITS + 7)/8)
#define SM2_MAX_PKEY_DATA_LENGTH		((EC_MAX_NBYTES + 1) * 6)

#define SM2_MAX_PLAINTEXT_LENGTH		65535
#define SM2_MAX_CIPHERTEXT_LENGTH		(SM2_MAX_PLAINTEXT_LENGTH + 2048)

typedef void *(*KDF_FUNC)(const void *in, size_t inlen, void *out, size_t *outlen);

typedef struct sm2encretstruct2012 {
  ASN1_INTEGER *x;
  ASN1_INTEGER *y;
  ASN1_OCTET_STRING *hash;
  ASN1_OCTET_STRING *ct;  // cipher text
} SM2_CIPHERT_2012;
DECLARE_ASN1_FUNCTIONS(SM2_CIPHERT_2012);

ASN1_SEQUENCE(SM2_CIPHERT_2012) = {
    ASN1_SIMPLE(SM2_CIPHERT_2012, x, ASN1_INTEGER),
    ASN1_SIMPLE(SM2_CIPHERT_2012, y, ASN1_INTEGER),
    ASN1_SIMPLE(SM2_CIPHERT_2012, hash, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2_CIPHERT_2012, ct,
                ASN1_OCTET_STRING)} ASN1_SEQUENCE_END(SM2_CIPHERT_2012);
IMPLEMENT_ASN1_FUNCTIONS(SM2_CIPHERT_2012);


/* GM/T003_2012 Defined Key Derive Function */
int KDF_GMT003_2012(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, const unsigned char *SharedInfo, size_t SharedInfolen, const EVP_MD *md)
{
    EVP_MD_CTX mctx;
    unsigned int counter;
    unsigned char ctr[4];
    size_t mdlen;
    int retval = 0;

    if (!out || !outlen) return retval;
    if (md == NULL) md = EVP_sm3();
    mdlen = EVP_MD_size(md);
    EVP_MD_CTX_init(&mctx);

    for (counter = 1;; counter++)
    {
        unsigned char dgst[EVP_MAX_MD_SIZE];

        EVP_DigestInit_ex(&mctx, md, NULL);
        ctr[0] = (unsigned char)((counter >> 24) & 0xFF);
        ctr[1] = (unsigned char)((counter >> 16) & 0xFF);
        ctr[2] = (unsigned char)((counter >> 8) & 0xFF);
        ctr[3] = (unsigned char)(counter & 0xFF);
        if (!EVP_DigestUpdate(&mctx, Z, Zlen))
            goto err;
        if (!EVP_DigestUpdate(&mctx, ctr, sizeof(ctr)))
            goto err;
        if (!EVP_DigestUpdate(&mctx, SharedInfo, SharedInfolen))
            goto err;
        if (!EVP_DigestFinal(&mctx, dgst, NULL))
            goto err;

        if (outlen > mdlen)
        {
            memcpy(out, dgst, mdlen);
            out += mdlen;
            outlen -= mdlen;
        }
        else
        {
            memcpy(out, dgst, outlen);
            memset(dgst, 0, mdlen);
            break;
        }
    }

    retval = 1;

err:
    EVP_MD_CTX_cleanup(&mctx);
    return retval;
}

/*Compute SM2 sign extra data: Z = HASH256(ENTL + ID + a + b + Gx + Gy + Xa + Ya)*/
int ECDSA_sm2_get_Z(const EC_KEY *ec_key, const EVP_MD *md, const char *uid, int uid_len, unsigned char *z_buf, size_t *z_len)
{
    EVP_MD_CTX *ctx;
    const EC_GROUP *group = NULL;
    BIGNUM *a = NULL, *b = NULL;
    const EC_POINT *point = NULL;
    unsigned char *z_source = NULL;
    int retval = 0;
    int deep, z_s_len;

    EC_POINT *pub_key = NULL;
    const BIGNUM *priv_key = NULL;

    if (md == NULL) md = EVP_sm3();
    if (*z_len < (size_t)(md->md_size))
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ARGUMENT);
        return 0;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ARGUMENT);
        goto err;
    }

    a = BN_new(), b = BN_new();
    if ((a == NULL) || (b == NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    if (!EC_GROUP_get_curve_GFp(group, NULL, a, b, NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    if ((point = EC_GROUP_get0_generator(group)) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    deep = (EC_GROUP_get_degree(group) + 7) / 8;
    if ((uid == NULL) || (uid_len <= 0))
    {
        uid = (const char *)"1234567812345678";
        uid_len = 16;
    }
   
    /*alloc z_source buffer*/
    while (!(z_source = (unsigned char *)OPENSSL_malloc(1 + 4 * deep)));

    /*ready to digest*/
    ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, md);

    z_s_len = 0;
    /*first: set the two bytes of uid bits + uid*/
    uid_len = uid_len * 8;
    
    z_source[z_s_len++] = (unsigned char)((uid_len >> 8) & 0xFF);
    z_source[z_s_len++] = (unsigned char)(uid_len & 0xFF);
    uid_len /= 8;
    EVP_DigestUpdate(ctx, z_source, z_s_len);
    EVP_DigestUpdate(ctx, uid, uid_len);

    /*second: add a and b*/
    BN_bn2bin(a, z_source + deep - BN_num_bytes(a));
    EVP_DigestUpdate(ctx, z_source, deep);
    BN_bn2bin(b, z_source + deep - BN_num_bytes(a));
    EVP_DigestUpdate(ctx, z_source, deep);
    
    /*third: add Gx and Gy*/
    z_s_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, z_source, (1 + 4 * deep), NULL);
    /*must exclude PC*/
    EVP_DigestUpdate(ctx, z_source + 1, z_s_len - 1);
    
    /*forth: add public key*/
    point = EC_KEY_get0_public_key(ec_key);
    if (!point)
    {
        priv_key = EC_KEY_get0_private_key(ec_key);
        if (!priv_key)
        {
            OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_PRIVATE_KEY);
            goto err;
        }

        pub_key = EC_POINT_new(group);
        if (!pub_key)
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, NULL))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }

        point = (const EC_POINT *)pub_key;
    }

    z_s_len = EC_POINT_point2oct(group, /*EC_KEY_get0_public_key(ec_key)*/point, POINT_CONVERSION_UNCOMPRESSED, z_source, (1 + 4 * deep), NULL);
    /*must exclude PC*/
    EVP_DigestUpdate(ctx, z_source + 1, z_s_len - 1);
    
    /*fifth: output digest*/
    EVP_DigestFinal(ctx, z_buf, (unsigned *)z_len);
    EVP_MD_CTX_destroy(ctx);
    
    retval = (int)(*z_len);

err:
    if (z_source) OPENSSL_free(z_source);
    if (pub_key) EC_POINT_free(pub_key);
    if (a) BN_free(a);
    if (b) BN_free(b);
    
    return retval;
}

int SM2_get_public_key_data(EC_KEY *ec_key, unsigned char *out, size_t *outlen)
{
	int ret = 0;
	const EC_GROUP *group;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *p;
	BIGNUM *x;
	BIGNUM *y;
	int nbytes;
	size_t len;

	if (!ec_key || !outlen || !(group = EC_KEY_get0_group(ec_key))) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/* degree is the bit length of field element, not the order of subgroup */
	nbytes = (EC_GROUP_get_degree(group) + 7)/8;
	len = nbytes * 6;

	if (!out) {
		*outlen = len;
		return 1;
	}
	if (*outlen < len) {
		OPENSSL_PUT_ERROR(SM2, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (!(bn_ctx = BN_CTX_new())) {
		OPENSSL_PUT_ERROR(SM2,  ERR_R_MALLOC_FAILURE);
		goto  end;
	}

	BN_CTX_start(bn_ctx);
	p = BN_CTX_get(bn_ctx);
	x = BN_CTX_get(bn_ctx);
	y = BN_CTX_get(bn_ctx);
	if (!y) {
		OPENSSL_PUT_ERROR(SM2,  ERR_R_MALLOC_FAILURE);
		goto end;
	}

	memset(out, 0, len);

	/* get curve coefficients */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_GROUP_get_curve_GFp(group, p, x, y, bn_ctx)) {
			OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
			goto end;
		}
	} else {
        goto end;
		// if (!EC_GROUP_get_curve_GF2m(group, p, x, y, bn_ctx)) {
		// 	OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
		// 	goto end;
		// }
	}

	/* when coeffiient a is zero, BN_bn2bin/BN_num_bytes return 0 */
	BN_bn2bin(x, out + nbytes - BN_num_bytes(x));
	out += nbytes;

	if (!BN_bn2bin(y, out + nbytes - BN_num_bytes(y))) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
		goto end;
	}
	out += nbytes;

	/* get curve generator coordinates */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group,
			EC_GROUP_get0_generator(group), x, y, bn_ctx)) {
			OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
			goto end;
		}
	} else {
        goto end;
		// if (!EC_POINT_get_affine_coordinates_GF2m(group,
		// 	EC_GROUP_get0_generator(group), x, y, bn_ctx)) {
		// 	OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
		// 	goto end;
		// }
	}

	if (!BN_bn2bin(x, out + nbytes - BN_num_bytes(x))) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
		goto end;
	}
	out += nbytes;

	if (!BN_bn2bin(y, out + nbytes - BN_num_bytes(y))) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
		goto end;
	}
	out += nbytes;

	/* get pub_key coorindates */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group,
			EC_KEY_get0_public_key(ec_key), x, y, bn_ctx)) {
			OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
			goto end;
		}
	} else {
        goto end;
		// if (!EC_POINT_get_affine_coordinates_GF2m(group,
		// 	EC_KEY_get0_public_key(ec_key), x, y, bn_ctx)) {
		// 	OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
		// 	goto end;
		// }
	}

	if (!BN_bn2bin(x, out + nbytes - BN_num_bytes(x))) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
		goto end;
	}
	out += nbytes;

	if (!BN_bn2bin(y, out + nbytes - BN_num_bytes(y))) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
		goto end;
	}

	*outlen = len;
	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	return ret;
}


int SM2_compute_id_digest(const EVP_MD *md, const char *id, size_t idlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char idbits[2];
	unsigned char pkdata[SM2_MAX_PKEY_DATA_LENGTH];
	unsigned int len;
	size_t size;

	if (!md || !id || idlen <= 0 || !outlen || !ec_key) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

#ifndef OPENSSL_NO_STRICT_GM
	if (EVP_MD_size(md) != SM2_DEFAULT_ID_DIGEST_LENGTH) {
		OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_DIGEST_ALGOR);
		return 0;
	}
#endif

	if (strlen(id) != idlen) {
		OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_SM2_ID);
		return 0;
	}
	if (idlen > SM2_MAX_ID_LENGTH || idlen <= 0) {
		OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ID_LENGTH);
		return 0;
	}

	if (!out) {
		*outlen = EVP_MD_size(md);
		return 1;
	}
	if (*outlen < (size_t)EVP_MD_size(md)) {
		OPENSSL_PUT_ERROR(SM2, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}


	/* get public key data from ec_key */
	size = sizeof(pkdata);
	if (!SM2_get_public_key_data(ec_key, pkdata, &size)) {
		//OPENSSL_PUT_ERROR(SM2, EC_R_GET_PUBLIC_KEY_DATA_FAILURE);
		goto end;
	}

	/* 2-byte id length in bits */
	idbits[0] = ((idlen * 8) >> 8) % 256;
	idbits[1] = (idlen * 8) % 256;

	len = EVP_MD_size(md);

	if (!(md_ctx = EVP_MD_CTX_new())
		|| !EVP_DigestInit_ex(md_ctx, md, NULL)
		|| !EVP_DigestUpdate(md_ctx, idbits, sizeof(idbits))
		|| !EVP_DigestUpdate(md_ctx, id, idlen)
		|| !EVP_DigestUpdate(md_ctx, pkdata, size)
		|| !EVP_DigestFinal_ex(md_ctx, out, &len)) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
		goto end;
	}

	*outlen = len;
	ret = 1;

end:
	EVP_MD_CTX_free(md_ctx);
        return ret;
}

/*
 * return msg_md( id_md(id, ec_key) || msg )
 */
int SM2_compute_message_digest(const EVP_MD *id_md, const EVP_MD *msg_md,
	const unsigned char *msg, size_t msglen, const char *id, size_t idlen,
	unsigned char *out, size_t *poutlen,
	EC_KEY *ec_key)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char za[EVP_MAX_MD_SIZE];
	size_t zalen = sizeof(za);
	unsigned int outlen;

	if (!id_md || !msg_md || !msg || msglen <= 0 || msglen > INT_MAX ||
		!id || idlen <= 0 || idlen > INT_MAX || !poutlen || !ec_key) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (EVP_MD_size(msg_md) <= 0) {
		OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_MD);
		return 0;
	}
	outlen = EVP_MD_size(msg_md);

	if (!out) {
		*poutlen = outlen;
		return 1;
	} else if (*poutlen < outlen) {
		OPENSSL_PUT_ERROR(SM2, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (!SM2_compute_id_digest(id_md, id, idlen, za, &zalen, ec_key)) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
		goto end;
	}

	/* msg_md(za || msg) */
	if (!(md_ctx = EVP_MD_CTX_new())
		|| !EVP_DigestInit_ex(md_ctx, msg_md, NULL)
		|| !EVP_DigestUpdate(md_ctx, za, zalen)
		|| !EVP_DigestUpdate(md_ctx, msg, msglen)
		|| !EVP_DigestFinal_ex(md_ctx, out, &outlen)) {
		OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
		goto end;
	}

	*poutlen = outlen;
	ret = 1;

end:
	EVP_MD_CTX_free(md_ctx);
	return ret;
}


/*SM2 Sign*/
ECDSA_SIG *sm2_do_sign(const uint8_t *dgst, size_t dgst_len, const EC_KEY *eckey)
{
    int ok = 0;
    BIGNUM *k = NULL, *e = NULL, *X = NULL, *order = NULL;
    EC_POINT *tmp_point = NULL;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    ECDSA_SIG *ret;
    const BIGNUM *d;
    
    group = EC_KEY_get0_group(eckey);
    d = EC_KEY_get0_private_key(eckey);
    if ((group == NULL) || (d == NULL))
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_MISSING_PARAMETERS);
        return NULL;
    }

    ret = ECDSA_SIG_new();
    if (!ret)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_SIGNATURE_MALLOC_FAILED);
        return NULL;
    }
    
    if (((ctx = BN_CTX_new()) == NULL) || ((order = BN_new()) == NULL) || ((X = BN_new()) == NULL) || ((e = BN_new()) == NULL) || ((k = BN_new()) == NULL))
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_SIGNATURE_MALLOC_FAILED);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if ((tmp_point = EC_POINT_new(group)) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    /*if dgest_len is too long, it must be truncate*/
    if (dgst_len > 32)
        dgst_len = 32;
    
    if (!BN_bin2bn(dgst, dgst_len, e))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    do
    {
        /*PART I: compute r*/
        /*first: generate a random number, it must be between 1~(order - 1)*/
#ifdef TEST_SM2
        BN_hex2bn(&k, "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F");
#else
        do
        {        
            if (!BN_rand_range(k, order))
            {
                OPENSSL_PUT_ERROR(SM2, SM2_R_RANDOM_NUMBER_GENERATION_FAILED);
                goto err;
            }
        } while (BN_is_zero(k)) ;
#endif
        /*second: compute k*G*/
        if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
        
#ifdef TEST_SM2
        printf("[line %d] Random Point: [%s]\n", __LINE__, EC_POINT_point2hex(group, tmp_point, EC_GROUP_get_point_conversion_form(group), NULL));
#endif
        if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
        {
            if (!EC_POINT_get_affine_coordinates_GFp(group, tmp_point, X, NULL, ctx))
            {
                OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
                goto err;
            }
        }
#ifndef OPENSSL_NO_EC2M
        else
        {
            /* NID_X9_62_characteristic_two_field */
            if (!EC_POINT_get_affine_coordinates_GF2m(group, tmp_point, X, NULL, ctx))
            {
                OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
                goto err;
            }
        }
#endif
        EC_POINT_free(tmp_point);

        /*third: compute r = (e + X) mod n*/
        if (!BN_mod_add(ret->r, e, X, order, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
            goto err;
        }

        /*and compute (r + k) mod n*/
        if (!BN_mod_add(X, ret->r, k, order, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
            goto err;
        }

        /*forth: detect r == 0 or r + k == n*/
        if (BN_is_zero(ret->r) || BN_is_zero(X))
            continue;
        
        /*PART II: compute s*/
        /*fifth: s = ((1 + d)^-1 * (k - rd)) mod n */
        if (!BN_one(X))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
            goto err;
        }
        
        /*compute: (1 + d) or (1 + d) mod n, thus need test*/        
        if (!BN_mod_add(X, d, X, order, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
            goto err;
        }
        
        /*compute: X ** -1 mod n*/
        if (!BN_mod_inverse(ret->s, X, order, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
            goto err;
        }
        
        /*compute: r * d mod n*/        
        if (!BN_mod_mul(X, ret->r, d, order, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
            goto err;
        }
        
        /*compute: (k - r*d) mod n*/
        if (!BN_mod_sub(X, k, X, order, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
            goto err;
        }
        
        /*compute: (((1 + d) ** -1) * (k - r * d)) mod n*/
        if (!BN_mod_mul(ret->s, ret->s, X, order, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
            goto err;
        }
    } while (BN_is_zero(ret->s));
    
    ok = 1;    

err:
    if (!ok)
    {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    if (ctx)
        BN_CTX_free(ctx);
    if (e)
        BN_clear_free(e);
    if (X)
        BN_clear_free(X);
    if (order)
        BN_free(order);
    if (k)
        BN_clear_free(k);

    return ret;
}

ECDSA_SIG *SM2_do_sign_ex(const unsigned char *dgst, int dgstlen,
	const BIGNUM *kp, const BIGNUM *xp, EC_KEY *ec_key)
{
	return sm2_do_sign(dgst, dgstlen, ec_key);
}
/*SM2 Verify*/
int sm2_do_verify(const uint8_t *dgst, size_t dgst_len, const ECDSA_SIG *sig, const EC_KEY *eckey)
{
    int ret = -1;
    BN_CTX *ctx;
    BIGNUM *order, *R, *x1, *e1, *t;
    EC_POINT *point = NULL;
    const EC_GROUP *group;
    const EC_POINT *pub_key;

    /* check input values */
    if ((eckey == NULL) || ((group = EC_KEY_get0_group(eckey)) == NULL) || ((pub_key = EC_KEY_get0_public_key(eckey)) == NULL) || (sig == NULL))
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_MISSING_PARAMETERS);
        return -1;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_VERIFY_MALLOC_FAILED);
        return -1;
    }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    R = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    e1 = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    if (!t)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (BN_is_zero(sig->r) || BN_is_negative(sig->r) || (BN_ucmp(sig->r, order) >= 0) || \
        BN_is_zero(sig->s) || BN_is_negative(sig->s) || (BN_ucmp(sig->s, order) >= 0))
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_BAD_SIGNATURE);
        /* signature is invalid */
        ret = 0;
        goto err;
    }

    /*if msgdigest length large to 32 then set length to 32*/
    if (dgst_len > 32)
        dgst_len = 32;
    if (!BN_bin2bn(dgst, dgst_len, e1))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }
    
    /*compute: t = (r1 + s1) mod n*/
    if (!BN_mod_add(t, sig->r, sig->s, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }
    
    /*detect t == 0*/
    if (BN_is_zero(t))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }
    
    /*compute: s1 * G + t * Pa*/
    if ((point = EC_POINT_new(group)) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_VERIFY_MALLOC_FAILED);
        goto err;
    }
    
    if (!EC_POINT_mul(group, point, sig->s, pub_key, t, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp(group, point, x1, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        /* NID_X9_62_characteristic_two_field */
        if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x1, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif
    
    if (!BN_nnmod(x1, x1, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mod_add(R, e1, x1, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }
    
    /*  if the signature is correct R is equal to sig->r */
    ret = (BN_ucmp(R, sig->r) == 0);

err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (point)
        EC_POINT_free(point);

    return ret;
}

int SM2_sign_ex(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen,
	const BIGNUM *k, const BIGNUM *x, EC_KEY *ec_key)
{
	ECDSA_SIG *s;

	if (type != NID_undef) {
		return 0;
	}

	RAND_seed((void*)dgst, dgstlen);

	if (!(s = SM2_do_sign_ex(dgst, dgstlen, k, x, ec_key))) {
		*siglen = 0;
		return 0;
	}

	*siglen = i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);

	return 1;
}

int SM2_sign(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen, EC_KEY *ec_key)
{
	return SM2_sign_ex(type, dgst, dgstlen, sig, siglen, NULL, NULL, ec_key);
}

int SM2_verify(int type, const unsigned char *dgst, int dgstlen,
	const unsigned char *sig, int siglen, EC_KEY *ec_key)
{
	ECDSA_SIG *s;
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	int derlen = -1;
	int ret = -1;

	if (type != NID_undef) {
		return ret;
	}

	if (!(s = ECDSA_SIG_new())) {
		return ret;
	}
	if (!d2i_ECDSA_SIG(&s, &p, siglen)) {
		goto err;
	}
	derlen = i2d_ECDSA_SIG(s, &der);
	if (derlen != siglen || memcmp(sig, der, derlen)) {
		goto err;
	}

	ret = sm2_do_verify(dgst, dgstlen, s, ec_key);

err:
	if (derlen > 0) {
		OPENSSL_cleanse(der, derlen);
		OPENSSL_free(der);
	}

	ECDSA_SIG_free(s);
	return ret;
}


/*SM2 Public Encrypt core function, out format is: C1 + C3 + C2*/
int __sm2_encrypt(unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen, const EVP_MD *md, EC_KEY *ec_key)
{
    int retval = 0;
    const EC_GROUP *group;
    BIGNUM *k = NULL, *order = NULL, *h = NULL;
    EC_POINT *C1 = NULL, *point = NULL;
    BN_CTX *ctx = NULL;
    const EC_POINT *pub_key = NULL;
    size_t loop, deep, nbytes;
    unsigned char *buf = NULL, *ckey = NULL;
    unsigned char C3[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *md_ctx = NULL;
    /*point_conversion_form_t from;*/
    int chktag;
    
    if (!outlen)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ARGUMENT);
        return retval;
    }

    if (!md) md = EVP_sm3();

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        return retval;
    }
    
    /*from = EC_GROUP_get_point_conversion_form(group);
    if ((from != POINT_CONVERSION_COMPRESSED) && (from != POINT_CONVERSION_UNCOMPRESSED) && (from != POINT_CONVERSION_HYBRID))
    {
        from = POINT_CONVERSION_UNCOMPRESSED;
    }*/
    /*from = POINT_CONVERSION_UNCOMPRESSED;*/

    deep = (EC_GROUP_get_degree(group) + 7) / 8;
    
    /*compute outlen, it must be conside to compressed point values*/
    /*
    if (from == POINT_CONVERSION_COMPRESSED)
        nbytes = 1 + deep + inlen + md->md_size;
    else
    */
    nbytes = 1 + deep * 2 /*C1*/ + inlen + md->md_size;
    if (!out)
    {
        *outlen = nbytes;
        return 1;
    }

    if (*outlen < nbytes)
    {
        *outlen = nbytes;
        return retval;
    }

    if ((ctx = BN_CTX_new()) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    order = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    if ((k == NULL) || (order == NULL) || (h == NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_GROUP_get_cofactor(group, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    C1 = EC_POINT_new(group);
    point = EC_POINT_new(group);
    if ((C1 == NULL) || (point == NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    if ((pub_key = EC_KEY_get0_public_key(ec_key)) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

redo:
#ifdef TEST_SM2
    BN_hex2bn(&k, "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F");
#else
    do
    {
        if (!BN_rand_range(k, order))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
            goto err;
        }
    } while (BN_is_zero(k)) ;
#endif // TEST_SM2
    
    /*compute C1 = [k]G = (x1, y1)*/
    if (!EC_POINT_mul(group, C1, k, NULL, NULL, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
#ifdef TEST_SM2
    printf("C1: [%s]\n", EC_POINT_point2hex(group, C1, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif // TEST_SM2

    /*compute S*/
    if (!EC_POINT_mul(group, point, NULL, pub_key, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    /*check S is at infinity*/
    if (EC_POINT_is_at_infinity(group, point))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    /*now, compute [k]P = (x2, y2)*/
    if (!EC_POINT_mul(group, point, NULL, pub_key, k, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
#ifdef TEST_SM2
    printf("[k]P: [%s]\n", EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif // TEST_SM2

    /*compute t = KDF_GMT003_2012(x2, y2)*/
    nbytes = deep * 2 + 1;
    if (buf == NULL)
        buf = OPENSSL_malloc(nbytes + 10);
    if (buf == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    nbytes = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, nbytes + 10, ctx);
    if (!nbytes)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    if (ckey == NULL)
        ckey = OPENSSL_malloc(inlen + 10);
    if (ckey == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (!KDF_GMT003_2012(ckey, inlen, (const unsigned char *)(buf + 1), nbytes - 1, NULL, 0, md))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*Test KDF Key ALL Bits Is Zero*/
    chktag = 1;
    for (loop = 0; loop < inlen; loop++)
        if (ckey[loop] & 0xFF)
        {
            chktag = 0;
            break;
        }
    if (chktag)
        goto redo;

#ifdef TEST_SM2
    printf("t:[");
    for (loop = 0; loop < inlen; loop++)
        printf("%02X", ckey[loop]);
    printf("]\n");
#endif // TEST_SM2

    /*compute C2: M xor t*/
    for (loop = 0; loop < inlen; loop++)
    {
        ckey[loop] ^= in[loop];
    }
#ifdef TEST_SM2
    printf("C2:[");
    for (loop = 0; loop < inlen; loop++)
        printf("%02X", ckey[loop]);
    printf("]\n");
#endif // TEST_SM2

    /*compute Digest of x2 + M + y2*/
    md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_DigestInit(md_ctx, md);
    EVP_DigestUpdate(md_ctx, buf + 1, deep);
    EVP_DigestUpdate(md_ctx, in, inlen);
    EVP_DigestUpdate(md_ctx, buf + 1 + deep, deep);
    EVP_DigestFinal(md_ctx, C3, NULL);
    EVP_MD_CTX_destroy(md_ctx);
#ifdef TEST_SM2
    printf("C3:[");
    for (loop = 0; loop < md->md_size; loop++)
        printf("%02X", C3[loop]);
    printf("]\n");
#endif // TEST_SM2
    
    /*Now output result*/
    nbytes = 0;
    /*output C1*/
    nbytes = EC_POINT_point2oct(group, C1, POINT_CONVERSION_UNCOMPRESSED, out, *outlen, ctx);
    
    /*second: output C3*/
    memcpy(out + nbytes, C3, md->md_size);
    nbytes += md->md_size;
    
    /*output C2*/
    memcpy(out + nbytes, ckey, inlen);
    nbytes += inlen;
    
    /*output: outlen*/
    *outlen = nbytes;
    retval = 1;

err:
    if (buf) OPENSSL_free(buf);
    if (ckey) OPENSSL_free(ckey);
    if (ctx) BN_CTX_end(ctx);
    if (ctx) BN_CTX_free(ctx);
    if (C1) EC_POINT_free(C1);
    if (point) EC_POINT_free(point);

    return retval;
}

/*SM2 Private Decrypt core function, in format is: C1 + C3 + C2*/
int __sm2_decrypt(unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen, const EVP_MD *md, EC_KEY *ec_key)
{
    int retval = 0;
    const EC_GROUP *group;
    const BIGNUM *k = NULL;
    BIGNUM *h = NULL;
    EC_POINT *C1 = NULL, *point = NULL;
    BN_CTX *ctx = NULL;
    size_t loop, deep, nbytes, from;
    unsigned char *buf = NULL, *ckey = NULL, C3[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *md_ctx = NULL;

    if (!outlen)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ARGUMENT);
        return retval;
    }

    if (!md) md = EVP_sm3();

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        return retval;
    }
    
    deep = (EC_GROUP_get_degree(group) + 7) / 8;
    
    /*compute outlen, it must be conside to compressed point values*/
    from = in[0] & 0xFE; /*exclude y_bit*/
    if ((from != POINT_CONVERSION_COMPRESSED) && (from != POINT_CONVERSION_UNCOMPRESSED) && (from != POINT_CONVERSION_HYBRID))
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ARGUMENT);
        goto err;
    }
    
    /*compute temporary public key octet bytes*/
    if (from == POINT_CONVERSION_COMPRESSED)
        nbytes = deep + 1;
    else
        nbytes = 2 * deep + 1;

    /*compute plain text length*/
    loop = inlen - nbytes - md->md_size;

    if (!out)
    {
        *outlen = loop;
        return 1;
    }

    if (*outlen < loop)
    {
        *outlen = loop;
        return retval;
    }
    
    if ((ctx = BN_CTX_new()) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    /*BN_CTX_start(ctx);*/
    h = BN_new();
    if (h == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_cofactor(group, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if ((k = EC_KEY_get0_private_key(ec_key)) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;    
    }
    
    /*GET C1*/
    C1 = EC_POINT_new(group);
    point = EC_POINT_new(group);
    if ((C1 == NULL) || (point == NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    if (!EC_POINT_oct2point(group, C1, in, nbytes, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    /*DETECT C1 is on this curve*/
    /*this is not need, because function EC_POINT_oct2point was do it*/
    if (!EC_POINT_is_on_curve(group, C1, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ARGUMENT);
        goto err;
    }
    
    /*DETECT [h]C1 is at infinity*/
    if (!EC_POINT_mul(group, point, NULL, C1, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    if (EC_POINT_is_at_infinity(group, point))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    /*COMPUTE [d]C1 into point*/
    if (!EC_POINT_mul(group, point, NULL, C1, k, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    /*OK, Now Compute t*/
    from = deep * 2 + 1;
    buf = OPENSSL_malloc(from + 10);
    if (buf == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    from = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, from + 10, ctx);
    if (!from)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
    
    ckey = OPENSSL_malloc(loop + 10);
    if (ckey == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (!KDF_GMT003_2012(ckey, loop, (const unsigned char *)(buf + 1), from - 1, NULL, 0, md))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*GET PLAIN TEXT, cipher text format is: C1 + C3 + C2*/
    for (from = 0; from < loop; from++)
    {
        ckey[from] ^= in[nbytes + md->md_size + from];
    }
    
    /*COMPUTE DIGEST*/
    md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_DigestInit(md_ctx, md);
    EVP_DigestUpdate(md_ctx, buf + 1, deep);
    EVP_DigestUpdate(md_ctx, ckey, loop);
    EVP_DigestUpdate(md_ctx, buf + 1 + deep, deep);
    EVP_DigestFinal(md_ctx, C3, NULL);
    EVP_MD_CTX_destroy(md_ctx);
    
    /*cipher text format is: C1 + C3 + C2*/
    if (memcmp(C3, in + nbytes, md->md_size))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }
    
    /*OK, SM2 Decrypt Successed*/
    memcpy(out, ckey, loop);
    *outlen = loop;
    
    retval = 1;
err:
    if (h) BN_free(h);
    if (C1) EC_POINT_free(C1);
    if (point) EC_POINT_free(point);
    if (buf) OPENSSL_free(buf);
    if (ckey) OPENSSL_free(ckey);
    if (ctx) 
    {
        /*BN_CTX_end(ctx);*/
        BN_CTX_free(ctx);
    }    

    return retval;
}

int __sm2_encrypt_gmt(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen, uint8_t *pbCdata, size_t *pndatalen, int nformat){
  int ok = 0;
  int nlen = 0, nindex = 0;
  size_t size = 0;
  uint8_t *p = 0, *ptmp = 0;
  SM2_CIPHERT_2012 *sm2ct = NULL;
  BIGNUM *bn = NULL;
  if (NULL == eckey || NULL == pbdata || NULL == pndatalen)
    return 0;
  if (NULL == pbCdata) {
    SM2_encrypt_with_recommended(pbdata,ndatalen,NULL,&size,eckey);
    size += 12;  // 30820000 0200 0200 0400
    *pndatalen = size;
    return 1;
  }
  if (ndatalen > 65535) {  // too large data
    goto err;
  }
  nlen = ndatalen + 512;
  p = (uint8_t *)OPENSSL_malloc(nlen);
  if (!p) {
    goto err;
  }
  sm2ct = SM2_CIPHERT_2012_new();
  if (!sm2ct) {
    goto err;
  }
  size = nlen;
  if (/*!SM2_ENC(eckey, pbdata, ndatalen, p, &size)*/
        !SM2_encrypt_with_recommended(pbdata,ndatalen,p,&size,eckey)
        ) {
    goto err;
  }
  nlen = (int)size;
  nindex = 1;
  bn = BN_bin2bn(p + nindex, 32, bn);
  sm2ct->x = BN_to_ASN1_INTEGER(bn, sm2ct->x);
  BN_zero(bn);
  nindex += 32;
  bn = BN_bin2bn(p + nindex, 32, bn);
  sm2ct->y = BN_to_ASN1_INTEGER(bn, sm2ct->y);
  nindex += 32;
  ASN1_OCTET_STRING_set(sm2ct->ct, p + nindex, nlen - nindex - 32);
  nindex = nlen - 32;
  ASN1_OCTET_STRING_set(sm2ct->hash, p + nindex, 32);
  nindex += 32;
  ptmp = pbCdata;
  if (!(nlen = i2d_SM2_CIPHERT_2012(sm2ct, &ptmp))) {
    goto err;
  }
  *pndatalen = nlen;
  ok = 1;
err:
  if (p) {
    OPENSSL_free(p);
  }
  if (bn) {
    BN_free(bn);
  }
  return ok;
}

#ifdef SM2DH_TEST
#define SM2DH_Kap_Func(a)    SM2DH_Kap_Func_##a
#else
#define SM2DH_Kap_Func(a)    a
#endif //SM2DH_TEST

/*SM2DH: Like ECDH, According to ECDH interface*/
/*SM2DH ex_data index detector*/

static struct CRYPTO_STATIC_MUTEX g_sm2_kap_lock = CRYPTO_STATIC_MUTEX_INIT;

int SM2DH_Kap_Func(SM2DH_get_ex_data_index)(void)
{
    static volatile int idx = -1;
    if (idx < 0) {
        CRYPTO_STATIC_MUTEX_lock_read(&g_sm2_kap_lock);
        if (idx < 0) {
            // idx = DH_get_ex_new_index( 0, "SM2DHKAP", NULL, NULL, NULL);
        }
        CRYPTO_STATIC_MUTEX_lock_read(&g_sm2_kap_lock);
    }
    return idx;
}

/*SM2DH ex_data apis*/
int SM2DH_Kap_Func(SM2DH_set_ex_data)(const EC_KEY *ecKey, void *datas)
{
    return 0;
    // return ECDH_set_ex_data(ecKey, SM2DH_Kap_Func(SM2DH_get_ex_data_index)(), datas);
}

void *SM2DH_Kap_Func(SM2DH_get_ex_data)(const EC_KEY *ecKey)
{
    return 0;
    // return ECDH_get_ex_data(ecKey, SM2DH_Kap_Func(SM2DH_get_ex_data_index)());
}

/*SM2DH: part 1 -- init*/
int SM2DH_Kap_Func(SM2DH_prepare)(EC_KEY *ecKey, int server, unsigned char *R, size_t *R_len)
{
    SM2DH_DATA *sm2Exdata = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *ecdhe_key = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int ret = -1;

    while (!(sm2Exdata = (SM2DH_DATA *)OPENSSL_malloc(sizeof(SM2DH_DATA))))
        ;
    memset(sm2Exdata, 0, sizeof(SM2DH_DATA));
    sm2Exdata->server = server;

    pkey = EVP_PKEY_new();
    if (!pkey)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }

    if (!EVP_PKEY_set1_EC_KEY(pkey, ecKey))
    {
        /*assign EC_KEY to PKEY error*/
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx)
    {
        /*Create EVP_PKEY_CTX error*/
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) != 1)
    {
        /*keygen init error*/
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, EC_GROUP_get_curve_name(EC_KEY_get0_group(ecKey))) <= 0)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &ecdhe_key) != 1)
    {
        /*keygen error*/
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }

    sm2Exdata->r_len = BN_bn2bin(EC_KEY_get0_private_key(ecdhe_key->pkey.ec), sm2Exdata->r);
    if (R)
    {
        size_t pub_len = EC_POINT_point2oct(EC_KEY_get0_group(ecdhe_key->pkey.ec), EC_KEY_get0_public_key(ecdhe_key->pkey.ec), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
        if (*R_len < pub_len)
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }

        pub_len = EC_POINT_point2oct(EC_KEY_get0_group(ecdhe_key->pkey.ec), EC_KEY_get0_public_key(ecdhe_key->pkey.ec), POINT_CONVERSION_UNCOMPRESSED, sm2Exdata->Rs, pub_len, NULL);
        if (!pub_len)
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
        sm2Exdata->Rs_len = (int)pub_len;
        *R_len = pub_len;
        memcpy(R, sm2Exdata->Rs, pub_len);
    }
    /*OK, Output EC private key And Public Key*/
    if (!SM2DH_Kap_Func(SM2DH_set_ex_data)(ecKey, (void *)(sm2Exdata)))
        goto err;

    ret = 1;

err:
    if (ecdhe_key) EVP_PKEY_free(ecdhe_key);
    if (pkey) EVP_PKEY_free(pkey);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);

    return ret;
}

/*detail: 1, Need define a struct to storage some informations, like: client_or_server_flag, ECPKPARAMETERS, EC_POINT*/
int SM2DH_Kap_Func(SM2DH_compute_key)(void *out, size_t outlen, const EC_POINT *pub_key, const EC_KEY *eckey, void *(*KDF) (const void *in, size_t inlen, void *out, size_t *outlen))

{
    SM2DH_DATA *sm2dhdata = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *Rs = NULL, *Rp = NULL; /*Rs: pubkey self*/
    EC_POINT *UorV = NULL;
    BIGNUM *Xs = NULL, *Xp = NULL, *r = NULL, *h = NULL, *t = NULL, *two_power_w = NULL, *order = NULL;
    const BIGNUM *priv_key;
    const EC_GROUP *group;
    int w;
    int ret = -1;
    size_t buflen, len;
    unsigned char *buf = NULL;

    if (outlen > INT_MAX)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key = EC_KEY_get0_private_key(eckey);
    if (priv_key == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_NO_PRIVATE_VALUE);
        goto err;
    }

    /*First: Detect Self And Peer Key Agreement Data ready, And others*/
    sm2dhdata = (SM2DH_DATA *)SM2DH_Kap_Func(SM2DH_get_ex_data)(eckey);
    if ((sm2dhdata == NULL) || !sm2dhdata->r_len || !sm2dhdata->Rp_len)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if (!sm2dhdata->r_len || !sm2dhdata->Rp_len)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    ctx = BN_CTX_new();
    Xs = BN_new();
    Xp = BN_new();
    h = BN_new();
    t = BN_new();
    two_power_w = BN_new();
    order = BN_new();

    if (!Xs || !Xp || !h || !t || !two_power_w || !order)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    r = BN_bin2bn((const unsigned char *)sm2dhdata->r, sm2dhdata->r_len, NULL);
    group = EC_KEY_get0_group(eckey);

    /*Second: Caculate -- w*/
    if (!EC_GROUP_get_order(group, order, ctx) || !EC_GROUP_get_cofactor(group, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    w = (BN_num_bits(order) + 1) / 2 - 1;
    if (!BN_lshift(two_power_w, BN_value_one(), w))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    /*Third: Caculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
    Rs = EC_POINT_new(group);
    Rp = EC_POINT_new(group);
    UorV = EC_POINT_new(group);

    if (!Rs || !Rp || !UorV)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_oct2point(group, Rs, sm2dhdata->Rs, (size_t)sm2dhdata->Rs_len, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_oct2point(group, Rp, sm2dhdata->Rp, (size_t)sm2dhdata->Rp_len, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*Test peer public key On curve*/
    if (!EC_POINT_is_on_curve(group, Rp, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*Get x*/
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp(group, Rs, Xs, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, Rp, Xp, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rs, Xs, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rp, Xp, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    /*x mod 2 ^ w*/
    /*Caculate Self x*/
    if (!BN_nnmod(Xs, Xs, two_power_w, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xs, Xs, two_power_w))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("X%d:[%s]\n", (sm2dhdata->server ? 2 : 1), BN_bn2hex(Xs));
#endif

    /*Caculate Peer x*/
    if (!BN_nnmod(Xp, Xp, two_power_w, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xp, Xp, two_power_w))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("x%d:[%s]\n", (sm2dhdata->server ? 1 : 2), BN_bn2hex(Xp));
#endif

    /*Forth: Caculate t*/
    if (!BN_mod_mul(t, Xs, r, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mod_add(t, t, priv_key, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("t%c:[%s]\n", (sm2dhdata->server ? 'B' : 'A'), BN_bn2hex(t));
#endif

    /*Fifth: Caculate V or U*/
    if (!BN_mul(t, t, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    /* [x]R */
    if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("[x%d]R%c:[%s]\n", (sm2dhdata->server ? 1 : 2), (sm2dhdata->server ? 'a' : 'b'), EC_POINT_point2hex(group, UorV, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif

    /* P + [x]R */
    if (!EC_POINT_add(group, UorV, UorV, pub_key, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("P%c + [x%d]R%c:[%s]\n", (sm2dhdata->server ? 'a' : 'b'), (sm2dhdata->server ? 1 : 2), (sm2dhdata->server ? 'a' : 'b'), EC_POINT_point2hex(group, UorV, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif

    if (!EC_POINT_mul(group, UorV, NULL, UorV, t, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
#ifdef SM2DH_TEST
    printf("%c = [h * t%C](P%c + [x%d]R%c):[%s]\n",
        (sm2dhdata->server ? 'V' : 'U'),
        (sm2dhdata->server ? 'B' : 'A'),
        (sm2dhdata->server ? 'a' : 'b'),
        (sm2dhdata->server ? 1 : 2),
        (sm2dhdata->server ? 'a' : 'b'),
        EC_POINT_point2hex(group, UorV, POINT_CONVERSION_UNCOMPRESSED, ctx)
        );
#endif

    /* Detect UorV is in */
    if (EC_POINT_is_at_infinity(group, UorV))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*Sixth: Caculate Key -- Need Xuorv, Yuorv, Zc, Zs, klen*/
    {
        /*
        size_t buflen, len;
        unsigned char *buf = NULL;
        */
        size_t elemet_len, idx;

        elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
        buflen = elemet_len * 2 + 32 * 2 + 1;    /*add 1 byte tag*/
        buf = (unsigned char *)OPENSSL_malloc(buflen + 10);
        if (!buf)
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        memset(buf, 0, buflen + 10);

        /*1 : Get public key for UorV, Notice: the first byte is a tag, not a valid char*/
        idx = EC_POINT_point2oct(group, UorV, 4, buf, buflen, ctx);
        if (!idx)
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }

        if (!sm2dhdata->server)
        {
            /*SIDE A*/
            len = buflen - idx;
            if (!ECDSA_sm2_get_Z(eckey, EVP_sm3(), (const char *)sm2dhdata->self_id, sm2dhdata->selfid_len, (unsigned char *)(buf + idx), &len))
            {
                goto err;
            }
#ifdef SM2DH_TEST
            {
                int i;

                printf("Za:[");
                for (i = 0; i < 32; i++)
                    printf("%02X", buf[idx + i] & 0xff);
                printf("]\n");
            }
#endif
            idx += len;
        }

        /*Caculate Peer Z*/
        {
            EC_KEY *tmp_key = EC_KEY_new();

            if (!tmp_key)
            {
                OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (!EC_KEY_set_group(tmp_key, group))
            {
                OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
                EC_KEY_free(tmp_key);
                goto err;
            }
            if (!EC_KEY_set_public_key(tmp_key, pub_key))
            {
                OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
                EC_KEY_free(tmp_key);
                goto err;
            }

            len = buflen - idx;

            /*SIDE B or SIDE A*/
            if (!ECDSA_sm2_get_Z(tmp_key, EVP_sm3(), (const char *)sm2dhdata->peer_id, sm2dhdata->peerid_len, (unsigned char *)(buf + idx), &len))
            {
                EC_KEY_free(tmp_key);
                goto err;
            }
#ifdef SM2DH_TEST
            {
                int i;

                if (sm2dhdata->server)
                    printf("Za:[");
                else
                    printf("Zb: [");
                for (i = 0; i < 32; i++)
                    printf("%02X", buf[idx + i] & 0xff);
                printf("]\n");
            }
#endif

            idx += len;
            EC_KEY_free(tmp_key);
        }

        if (sm2dhdata->server)
        {
            /*SIDE B*/
            len = buflen - idx;
            if (!ECDSA_sm2_get_Z(eckey, EVP_sm3(), (const char *)sm2dhdata->self_id, sm2dhdata->selfid_len, (unsigned char *)(buf + idx), &len))
            {
                goto err;
            }
#ifdef SM2DH_TEST
            {
                int i;

                printf("Zb:[");
                for (i = 0; i < 32; i++)
                    printf("%02X", buf[idx + i] & 0xff);
                printf("]\n");
            }
#endif
            idx += len;
        }

        len = outlen;
        if (!KDF_GMT003_2012(out, len, (const unsigned char *)(buf + 1), idx - 1, NULL, 0, EVP_sm3()))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    /*Seventh: caculate checksum (if need)*/
    if (sm2dhdata->checksum)
    {
        EVP_MD_CTX md_ctx;

        unsigned char h_Yuorv[64 + 1 + EVP_MAX_MD_SIZE];
        unsigned char *h_Xuorv = NULL;
        size_t elemet_len, idx, idy;

        elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
        len = elemet_len * 5 + 32 * 2;
        h_Xuorv = (unsigned char *)OPENSSL_malloc(len + 10);
        if (!h_Xuorv)
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memset(h_Xuorv, 0, len + 10);

        /*buf: 1Tag + Xuorv + Yuorv + Za + Zb*/
        idx = 0;
        memcpy(h_Xuorv + idx, buf + 1, elemet_len);
        idx += elemet_len;
        memcpy(h_Yuorv + 1, buf + 1 + elemet_len, elemet_len);
        idy = 1 + elemet_len;

        /*Za + Zb*/
        memcpy(h_Xuorv + idx, buf + 1 + elemet_len * 2, 64);
        idx += 64;

        if (sm2dhdata->server)
        {
            memcpy(h_Xuorv + idx, sm2dhdata->Rp + 1, sm2dhdata->Rp_len - 1);
            idx += (sm2dhdata->Rp_len - 1);
            memcpy(h_Xuorv + idx, sm2dhdata->Rs + 1, sm2dhdata->Rs_len - 1);
            idx += (sm2dhdata->Rs_len - 1);
        }
        else
        {
            memcpy(h_Xuorv + idx, sm2dhdata->Rs + 1, sm2dhdata->Rs_len - 1);
            idx += (sm2dhdata->Rs_len - 1);
            memcpy(h_Xuorv + idx, sm2dhdata->Rp + 1, sm2dhdata->Rp_len - 1);
            idx += (sm2dhdata->Rp_len - 1);
        }

        EVP_DigestInit(&md_ctx, EVP_sm3());
        EVP_DigestUpdate(&md_ctx, h_Xuorv, idx);
        EVP_DigestFinal(&md_ctx, h_Yuorv + idy, NULL);
        idy += 32;
        EVP_MD_CTX_cleanup(&md_ctx);

        if (sm2dhdata->server)
        {
            /*SIDE B*/
            h_Yuorv[0] = (unsigned char)0x02;
            EVP_DigestInit(&md_ctx, EVP_sm3());
            EVP_DigestUpdate(&md_ctx, h_Yuorv, idy);
            EVP_DigestFinal(&md_ctx, sm2dhdata->s_checksum, NULL);
            EVP_MD_CTX_cleanup(&md_ctx);

            h_Yuorv[0] = (unsigned char)0x03;
            EVP_DigestInit(&md_ctx, EVP_sm3());
            EVP_DigestUpdate(&md_ctx, h_Yuorv, idy);
            EVP_DigestFinal(&md_ctx, sm2dhdata->e_checksum, NULL);
            EVP_MD_CTX_cleanup(&md_ctx);
        }
        else
        {
            /*SIDE A*/
            h_Yuorv[0] = (unsigned char)0x03;
            EVP_DigestInit(&md_ctx, EVP_sm3());
            EVP_DigestUpdate(&md_ctx, h_Yuorv, idy);
            EVP_DigestFinal(&md_ctx, sm2dhdata->s_checksum, NULL);
            EVP_MD_CTX_cleanup(&md_ctx);

            h_Yuorv[0] = (unsigned char)0x02;
            EVP_DigestInit(&md_ctx, EVP_sm3());
            EVP_DigestUpdate(&md_ctx, h_Yuorv, idy);
            EVP_DigestFinal(&md_ctx, sm2dhdata->e_checksum, NULL);
            EVP_MD_CTX_cleanup(&md_ctx);

        }

        OPENSSL_free(h_Xuorv);

        SM2DH_Kap_Func(SM2DH_set_ex_data)(eckey, sm2dhdata);

    }

    ret = outlen;

err:
    if (r) BN_free(r);
    if (Xs) BN_free(Xs);
    if (Xp) BN_free(Xp);
    if (h) BN_free(h);
    if (t) BN_free(t);
    if (two_power_w) BN_free(two_power_w);
    if (order) BN_free(order);
    if (Rs) EC_POINT_free(Rs);
    if (Rp) EC_POINT_free(Rp);
    if (UorV) EC_POINT_free(UorV);
    if (buf) OPENSSL_free(buf);
    if (ctx) BN_CTX_free(ctx);

    return ret;
}

/*Get SM2DH ensure information*/
int SM2DH_Kap_Func(SM2DH_get_ensure_checksum)(void *out, EC_KEY *eckey)
{
    SM2DH_DATA *sm2dhdata = NULL;
    const EVP_MD *md = EVP_sm3();

    sm2dhdata = (SM2DH_DATA *)SM2DH_Kap_Func(SM2DH_get_ex_data)(eckey);

    if (sm2dhdata == NULL)
    {
        return 0;
    }

    if (out)
    {
        memcpy(out, sm2dhdata->e_checksum, md->md_size);
    }

    return md->md_size;
}

int SM2DH_Kap_Func(SM2DH_get_send_checksum)(void *out, EC_KEY *eckey)
{
    SM2DH_DATA *sm2dhdata = NULL;
    const EVP_MD *md = EVP_sm3();

    sm2dhdata = (SM2DH_DATA *)SM2DH_Kap_Func(SM2DH_get_ex_data)(eckey);

    if (sm2dhdata == NULL)
    {
        return 0;
    }

    if (out)
    {
        memcpy(out, sm2dhdata->s_checksum, md->md_size);
    }

    return md->md_size;
}

// static int SM2DH_Kap_Func(SM2DH_set_checksum)(EC_KEY *eckey, int checksum)
// {
//     SM2DH_DATA *sm2dhdata = NULL;

//     sm2dhdata = (SM2DH_DATA *)SM2DH_Kap_Func(SM2DH_get_ex_data)(eckey);

//     if (sm2dhdata == NULL)
//     {
//         return 0;
//     }

//     sm2dhdata->checksum = (checksum ? 1 : 0);

//     return SM2DH_Kap_Func(SM2DH_set_ex_data)(eckey, (void *)sm2dhdata);
// }

int SM2DH_Kap_Func(SM2Kap_compute_key)(void *out, size_t outlen, int server,\
    const char *peer_uid, int peer_uid_len, const char *self_uid, int self_uid_len, \
    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key, const EC_KEY *peer_pub_key, const EC_KEY *self_eckey, \
    const EVP_MD *md)
{
    BN_CTX *ctx = NULL;
    EC_POINT *UorV = NULL;
    const EC_POINT *Rs, *Rp;
    BIGNUM *Xs = NULL, *Xp = NULL, *h = NULL, *t = NULL, *two_power_w = NULL, *order = NULL;
    const BIGNUM *priv_key, *r;
    const EC_GROUP *group;
    int w;
    int ret = -1;
    size_t buflen, len;
    unsigned char *buf = NULL;

    if (outlen > INT_MAX)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!peer_pub_key || !self_eckey)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_NO_PRIVATE_VALUE);
        goto err;
    }
    
    priv_key = EC_KEY_get0_private_key(self_eckey);
    if (!priv_key)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_NO_PRIVATE_VALUE);
        goto err;
    }

    if (!peer_ecdhe_key || !self_ecdhe_key)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    Rs = EC_KEY_get0_public_key(self_ecdhe_key);
    Rp = EC_KEY_get0_public_key(peer_ecdhe_key);
    r = EC_KEY_get0_private_key(self_ecdhe_key);

    if (!Rs || !Rp || !r)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    ctx = BN_CTX_new();
    Xs = BN_new();
    Xp = BN_new();
    h = BN_new();
    t = BN_new();
    two_power_w = BN_new();
    order = BN_new();

    if (!Xs || !Xp || !h || !t || !two_power_w || !order)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    group = EC_KEY_get0_group(self_eckey);

    /*Second: Caculate -- w*/
    if (!EC_GROUP_get_order(group, order, ctx) || !EC_GROUP_get_cofactor(group, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    w = (BN_num_bits(order) + 1) / 2 - 1;
    if (!BN_lshift(two_power_w, BN_value_one(), w))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    /*Third: Caculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
    UorV = EC_POINT_new(group);

    if (!UorV)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*Test peer public key On curve*/
    if (!EC_POINT_is_on_curve(group, Rp, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*Get x*/
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp(group, Rs, Xs, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, Rp, Xp, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rs, Xs, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rp, Xp, NULL, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    /*x mod 2 ^ w*/
    /*Caculate Self x*/
    if (!BN_nnmod(Xs, Xs, two_power_w, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xs, Xs, two_power_w))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    /*Caculate Peer x*/
    if (!BN_nnmod(Xp, Xp, two_power_w, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xp, Xp, two_power_w))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    /*Forth: Caculate t*/
    if (!BN_mod_mul(t, Xs, r, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mod_add(t, t, priv_key, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    /*Fifth: Caculate V or U*/
    if (!BN_mul(t, t, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    /* [x]R */
    if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /* P + [x]R */
    if (!EC_POINT_add(group, UorV, UorV, EC_KEY_get0_public_key(peer_pub_key), ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_mul(group, UorV, NULL, UorV, t, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /* Detect UorV is in */
    if (EC_POINT_is_at_infinity(group, UorV))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*Sixth: Caculate Key -- Need Xuorv, Yuorv, Zc, Zs, klen*/
    {
        /*
        size_t buflen, len;
        unsigned char *buf = NULL;
        */
        size_t elemet_len, idx;

        elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
        buflen = elemet_len * 2 + 32 * 2 + 1;    /*add 1 byte tag*/
        buf = (unsigned char *)OPENSSL_malloc(buflen + 10);
        if (!buf)
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        memset(buf, 0, buflen + 10);

        /*1 : Get public key for UorV, Notice: the first byte is a tag, not a valid char*/
        idx = EC_POINT_point2oct(group, UorV, 4, buf, buflen, ctx);
        if (!idx)
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }

        if (!server)
        {
            /*SIDE A*/
            len = buflen - idx;
            if (!ECDSA_sm2_get_Z(self_eckey, md, self_uid, self_uid_len, (unsigned char *)(buf + idx), &len))
            {
                goto err;
            }
            len = 32;
            idx += len;
        }

        /*Caculate Peer Z*/
        len = buflen - idx;
        if (!ECDSA_sm2_get_Z(peer_pub_key, md, peer_uid, peer_uid_len, (unsigned char *)(buf + idx), &len))
        {
            goto err;
        }
        len = 32;
        idx += len;

        if (server)
        {
            /*SIDE B*/
            len = buflen - idx;
            if (!ECDSA_sm2_get_Z(self_eckey, md, self_uid, self_uid_len, (unsigned char *)(buf + idx), &len))
            {
                goto err;
            }
	     len = 32;
            idx += len;
        }

        len = outlen;
        if (!KDF_GMT003_2012(out, len, (const unsigned char *)(buf + 1), idx - 1, NULL, 0, md))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    ret = outlen;

err:
    if (Xs) BN_free(Xs);
    if (Xp) BN_free(Xp);
    if (h) BN_free(h);
    if (t) BN_free(t);
    if (two_power_w) BN_free(two_power_w);
    if (order) BN_free(order);
    if (UorV) EC_POINT_free(UorV);
    if (buf) OPENSSL_free(buf);
    if (ctx) BN_CTX_free(ctx);

    return ret;
}

ASN1_SEQUENCE(SM2ENC) = {
    ASN1_SIMPLE(SM2ENC, x, ASN1_INTEGER),
    ASN1_SIMPLE(SM2ENC, y, ASN1_INTEGER),
    ASN1_SIMPLE(SM2ENC, m, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2ENC, c, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SM2ENC)

DECLARE_ASN1_FUNCTIONS_const(SM2ENC)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(SM2ENC, SM2ENC)
IMPLEMENT_ASN1_FUNCTIONS_const(SM2ENC)

// SM2ENC *SM2_do_encrypt(const EVP_MD *md,
// 	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
// {
// 	SM2ENC *ret = NULL;
// 	SM2ENC *cv = NULL;
// 	const EC_GROUP *group;
// 	const EC_POINT *pub_key;
// 	KDF_FUNC kdf;
// 	EC_POINT *ephem_point = NULL;
// 	EC_POINT *share_point = NULL;
// 	BIGNUM *n = NULL;
// 	BIGNUM *h = NULL;
// 	BIGNUM *k = NULL;
// 	BN_CTX *bn_ctx = NULL;
// 	EVP_MD_CTX *md_ctx = NULL;

// 	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
// 	int nbytes;
// 	size_t len;
// 	size_t i;
// 	unsigned int hashlen;

// 	/* check arguments */
// 	if (!md || !in || !ec_key) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
// 		return 0;
// 	}

// 	if (inlen <= 0 || inlen > SM2_MAX_PLAINTEXT_LENGTH) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_PLAINTEXT_LENGTH);
// 		return 0;
// 	}

// 	if (!(kdf = KDF_get_x9_63(md))) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_DIGEST_ALGOR);
// 		return 0;
// 	}

// 	if (!(group = EC_KEY_get0_group(ec_key))
// 		|| !(pub_key = EC_KEY_get0_public_key(ec_key))) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_EC_KEY);
// 		return 0;
// 	}

// 	/* malloc */
// 	if (!(cv = SM2CiphertextValue_new())
// 		|| !(ephem_point = EC_POINT_new(group))
// 		|| !(share_point = EC_POINT_new(group))
// 		|| !(n = BN_new())
// 		|| !(h = BN_new())
// 		|| !(k = BN_new())
// 		|| !(bn_ctx = BN_CTX_new())
// 		|| !(md_ctx = EVP_MD_CTX_new())) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
// 		goto end;
// 	}

// 	if (!ASN1_OCTET_STRING_set(cv->c, NULL, (int)inlen)
// 		|| !ASN1_OCTET_STRING_set(cv->m, NULL, EVP_MD_size(md))) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
// 		goto end;
// 	}

// 	/* init ec domain parameters */
// 	if (!EC_GROUP_get_order(group, n, bn_ctx)) {
// 		//OPENSSL_PUT_ERROR(SM2, EC_R_ERROR);
// 		goto end;
// 	}

// 	if (!EC_GROUP_get_cofactor(group, h, bn_ctx)) {
// 		//OPENSSL_PUT_ERROR(SM2, EC_R_ERROR);
// 		goto end;
// 	}

// 	nbytes = (EC_GROUP_get_degree(group) + 7) / 8;

// 	/* check [h]P_B != O */
// 	if (!EC_POINT_mul(group, share_point, NULL, pub_key, h, bn_ctx)) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 		goto end;
// 	}

// 	if (EC_POINT_is_at_infinity(group, share_point)) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_PUBLIC_KEY);
// 		goto end;
// 	}

// 	do
// 	{
// 		size_t size;

// 		/* rand k in [1, n-1] */
// 		do {
// 			BN_rand_range(k, n);
// 		} while (BN_is_zero(k));

// 		/* compute ephem_point [k]G = (x1, y1) */
// 		if (!EC_POINT_mul(group, ephem_point, k, NULL, NULL, bn_ctx)) {
// 			OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 			goto end;
// 		}

// 		/* compute ECDH share_point [k]P_B = (x2, y2) */
// 		if (!EC_POINT_mul(group, share_point, NULL, pub_key, k, bn_ctx)) {
// 			OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 			goto end;
// 		}

// 		/* compute t = KDF(x2 || y2, klen) */
// 		if (!(len = EC_POINT_point2oct(group, share_point,
// 			POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
// 			OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 			goto end;
// 		}

// 		size = cv->c->length;
// 		kdf(buf + 1, len - 1, cv->c->data, &size);
// 		if (size != inlen) {
// 			//OPENSSL_PUT_ERROR(SM2, SM2_R_KDF_FAILURE);
// 			goto end;
// 		}

// 		/* ASN1_OCTET_STRING_is_zero in asn1.h and a_octet.c */
// 	} while (ASN1_OCTET_STRING_is_zero(cv->c));

// 	/* set x/yCoordinates as (x1, y1) */
// 	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
// 		if (!EC_POINT_get_affine_coordinates_GFp(group, ephem_point,
// 			cv->x, cv->y, bn_ctx)) {
// 			OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 			goto end;
// 		}
// 	} else {
// 		if (!EC_POINT_get_affine_coordinates_GF2m(group, ephem_point,
// 			cv->x, cv->y, bn_ctx)) {
// 			OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 			goto end;
// 		}
// 	}

// 	/* ciphertext = t xor in */
// 	for (i = 0; i < inlen; i++) {
// 		cv->c->data[i] ^= in[i];
// 	}

// 	/* generate hash = Hash(x2 || M || y2) */
// 	hashlen = cv->m->length;
// 	if (!EVP_DigestInit_ex(md_ctx, md, NULL)
// 		|| !EVP_DigestUpdate(md_ctx, buf + 1, nbytes)
// 		|| !EVP_DigestUpdate(md_ctx, in, inlen)
// 		|| !EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)
// 		|| !EVP_DigestFinal_ex(md_ctx, cv->m->data, &hashlen)) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
// 		goto end;
// 	}

// 	ret = cv;
// 	cv = NULL;

// end:
// 	SM2CiphertextValue_free(cv);
// 	EC_POINT_free(share_point);
// 	EC_POINT_free(ephem_point);
// 	BN_free(n);
// 	BN_free(h);
// 	BN_clear_free(k);
// 	BN_CTX_free(bn_ctx);
// 	EVP_MD_CTX_free(md_ctx);
// 	return ret;
// }

// int SM2_do_decrypt(const EVP_MD *md, const SM2ENC *cv,
// 	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
// {
// 	int ret = 0;
// 	const EC_GROUP *group;
// 	const BIGNUM *pri_key;
// 	KDF_FUNC kdf;
// 	EC_POINT *point = NULL;
// 	EC_POINT *tmp_point = NULL;
// 	BIGNUM *n = NULL;
// 	BIGNUM *h = NULL;
// 	BN_CTX *bn_ctx = NULL;
// 	EVP_MD_CTX *md_ctx = NULL;
// 	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
// 	unsigned char mac[EVP_MAX_MD_SIZE];
// 	unsigned int maclen = sizeof(mac);
// 	int nbytes, len, i;

// 	/* check arguments */
// 	if (!md || !cv || !outlen || !ec_key) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
// 		return 0;
// 	}

// 	if (!(kdf = KDF_get_x9_63(md))) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_DIGEST_ALGOR);
// 		return 0;
// 	}

// 	if (!cv->x || !cv->y || !cv->m || !cv->c) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
// 		return 0;
// 	}

// 	if (cv->m->length != EVP_MD_size(md)) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
// 		return 0;
// 	}

// 	if (cv->c->length <= 0
// 		|| cv->c->length > SM2_MAX_PLAINTEXT_LENGTH) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
// 		return 0;
// 	}

// 	if (!(group = EC_KEY_get0_group(ec_key))
// 		|| !(pri_key = EC_KEY_get0_private_key(ec_key))) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_EC_KEY);
// 		return 0;
// 	}

// 	if (!out) {
// 		*outlen = cv->c->length;
// 		return 1;
// 	}
// 	/*
// 	if (*outlen < cv->ciphertext->length) {
// 		OPENSSL_PUT_ERROR(SM2, SM2_R_BUFFER_TOO_SMALL);
// 		return 0;
// 	}
// 	*/

// 	/* malloc */
// 	point = EC_POINT_new(group);
// 	tmp_point = EC_POINT_new(group);
// 	n = BN_new();
// 	h = BN_new();
// 	bn_ctx = BN_CTX_new();
// 	md_ctx = EVP_MD_CTX_new();
// 	if (!point || !n || !h || !bn_ctx || !md_ctx) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
// 		goto end;
// 	}

// 	/* init ec domain parameters */
// 	if (!EC_GROUP_get_order(group, n, bn_ctx)) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 		goto end;
// 	}

// 	if (!EC_GROUP_get_cofactor(group, h, bn_ctx)) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 		goto end;
// 	}

// 	nbytes = (EC_GROUP_get_degree(group) + 7) / 8;

// 	/* get x/yCoordinates as C1 = (x1, y1) */
// 	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
// 		if (!EC_POINT_set_affine_coordinates_GFp(group, point,
// 			cv->x, cv->y, bn_ctx)) {
// 			//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
// 			goto end;
// 		}
// 	} else {
// 		if (!EC_POINT_set_affine_coordinates_GF2m(group, point,
// 			cv->x, cv->y, bn_ctx)) {
// 			//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
// 			goto end;
// 		}
// 	}

// 	/* check [h]C1 != O */
// 	if (!EC_POINT_mul(group, tmp_point, NULL, point, h, bn_ctx)) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 		goto end;
// 	}

// 	if (EC_POINT_is_at_infinity(group, tmp_point)) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
// 		goto end;
// 	}

// 	/* compute ECDH [d]C1 = (x2, y2) */
// 	if (!EC_POINT_mul(group, point, NULL, point, pri_key, bn_ctx)) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 		goto end;
// 	}

// 	if (!(len = EC_POINT_point2oct(group, point,
// 		POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
// 		goto end;
// 	}

// 	/* compute t = KDF(x2 || y2, clen) */
// 	*outlen = cv->c->length;
// 	kdf(buf + 1, len - 1, out, outlen);


// 	/* compute M = C2 xor t */
// 	for (i = 0; i < cv->c->length; i++) {
// 		out[i] ^= cv->c->data[i];
// 	}

// 	/* check hash == Hash(x2 || M || y2) */
// 	if (!EVP_DigestInit_ex(md_ctx, md, NULL)
// 		|| !EVP_DigestUpdate(md_ctx, buf + 1, nbytes)
// 		|| !EVP_DigestUpdate(md_ctx, out, *outlen)
// 		|| !EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)
// 		|| !EVP_DigestFinal_ex(md_ctx, mac, &maclen)) {
// 		OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
// 		goto end;
// 	}

// 	if (OPENSSL_memcmp(cv->m->data, mac, maclen) != 0) {
// 		//OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
// 		goto end;
// 	}

// 	ret = 1;
// end:
// 	EC_POINT_free(point);
// 	EC_POINT_free(tmp_point);
// 	BN_free(n);
// 	BN_free(h);
// 	BN_CTX_free(bn_ctx);
// 	EVP_MD_CTX_free(md_ctx);
// 	return ret;
// }

/* SM2 Public Encrypt core function: return NULL failure */
SM2ENC *sm2_encrypt(const unsigned char *in, size_t inlen, const EVP_MD *md, EC_KEY *ec_key)
{
    const EC_GROUP *group;
    BIGNUM *k = NULL, *order = NULL, *h = NULL, *x = NULL, *y = NULL;
    EC_POINT *C1 = NULL, *point = NULL;
    BN_CTX *ctx = NULL;
    const EC_POINT *pub_key = NULL;
    size_t loop, deep, nbytes;
    unsigned char *buf = NULL, *ckey = NULL;
    unsigned char C3[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *md_ctx = NULL;
    /*point_conversion_form_t from;*/
    int chktag;
    SM2ENC *retval = NULL;
    int ok = 0;

    if (!md) md = EVP_sm3();

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        return NULL;
    }

    deep = (EC_GROUP_get_degree(group) + 7) / 8;

    nbytes = 1 + deep * 2 /*C1*/ + inlen + md->md_size;

    if ((ctx = BN_CTX_new()) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    order = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if ((k == NULL) || (order == NULL) || (h == NULL) || (x == NULL) || (y == NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_GROUP_get_cofactor(group, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    C1 = EC_POINT_new(group);
    point = EC_POINT_new(group);
    if ((C1 == NULL) || (point == NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if ((pub_key = EC_KEY_get0_public_key(ec_key)) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

redo:
#ifdef TEST_SM2
    BN_hex2bn(&k, "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F");
#else
    do
    {
        if (!BN_rand_range(k, order))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
            goto err;
        }
    } while (BN_is_zero(k));
#endif // TEST_SM2

    /*compute C1 = [k]G = (x1, y1)*/
    if (!EC_POINT_mul(group, C1, k, NULL, NULL, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
#ifdef TEST_SM2
    printf("C1: [%s]\n", EC_POINT_point2hex(group, C1, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif // TEST_SM2

    /*compute S*/
    if (!EC_POINT_mul(group, point, NULL, pub_key, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*check S is at infinity*/
    if (EC_POINT_is_at_infinity(group, point))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*now, compute [k]P = (x2, y2)*/
    if (!EC_POINT_mul(group, point, NULL, pub_key, k, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }
#ifdef TEST_SM2
    printf("[k]P: [%s]\n", EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx));
#endif // TEST_SM2

    /*compute t = KDF_GMT003_2012(x2, y2)*/
    nbytes = deep * 2 + 1;
    if (buf == NULL)
        buf = OPENSSL_malloc(nbytes + 10);
    if (buf == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    nbytes = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, nbytes + 10, ctx);
    if (!nbytes)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (ckey == NULL)
        ckey = OPENSSL_malloc(inlen + 10);
    if (ckey == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (!KDF_GMT003_2012(ckey, inlen, (const unsigned char *)(buf + 1), nbytes - 1, NULL, 0, md))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*Test KDF Key ALL Bits Is Zero*/
    chktag = 1;
    for (loop = 0; loop < inlen; loop++)
        if (ckey[loop] & 0xFF)
        {
            chktag = 0;
            break;
        }
    if (chktag)
        goto redo;

#ifdef TEST_SM2
    printf("t:[");
    for (loop = 0; loop < inlen; loop++)
        printf("%02X", ckey[loop]);
    printf("]\n");
#endif // TEST_SM2

    /*ALLOC Return Value*/
    retval = SM2ENC_new();
    if (!retval)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*compute C2: M xor t*/
    for (loop = 0; loop < inlen; loop++)
    {
        ckey[loop] ^= in[loop];
    }
#ifdef TEST_SM2
    printf("C2:[");
    for (loop = 0; loop < inlen; loop++)
        printf("%02X", ckey[loop]);
    printf("]\n");
#endif // TEST_SM2

    if (!ASN1_OCTET_STRING_set(retval->c, (const unsigned char *)ckey, inlen))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
        goto err;
    }

    /*compute Digest of x2 + M + y2*/
    md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_DigestInit(md_ctx, md);
    EVP_DigestUpdate(md_ctx, buf + 1, deep);
    EVP_DigestUpdate(md_ctx, in, inlen);
    EVP_DigestUpdate(md_ctx, buf + 1 + deep, deep);
    EVP_DigestFinal(md_ctx, C3, NULL);
    EVP_MD_CTX_destroy(md_ctx);
#ifdef TEST_SM2
    printf("C3:[");
    for (loop = 0; loop < md->md_size; loop++)
        printf("%02X", C3[loop]);
    printf("]\n");
#endif // TEST_SM2

    if (!ASN1_OCTET_STRING_set(retval->m, (const unsigned char *)C3, md->md_size))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
        goto err;
    }

    /*output C1*/
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp((const EC_GROUP *)group, (const EC_POINT *)C1, x, y, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        /* NID_X9_62_characteristic_two_field */
        if (!EC_POINT_get_affine_coordinates_GF2m((const EC_GROUP *)group, (const EC_POINT *)C1, x, y, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    if (!BN_to_ASN1_INTEGER((const BIGNUM *)x, retval->x) || !BN_to_ASN1_INTEGER((const BIGNUM *)y, retval->y))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
        goto err;
    }

    ok = 1;

err:
    if (buf) OPENSSL_free(buf);
    if (ckey) OPENSSL_free(ckey);
    if (ctx) BN_CTX_end(ctx);
    if (ctx) BN_CTX_free(ctx);
    if (C1) EC_POINT_free(C1);
    if (point) EC_POINT_free(point);
    if (!ok)
    {
        if (retval)
        {
            SM2ENC_free(retval);
            retval = NULL;
        }
    }

    return retval;
}

/* SM2 Private Decrypt core function: return ZERO failure */
int sm2_decrypt(unsigned char *out, size_t *outlen, const SM2ENC *in, const EVP_MD *md, EC_KEY *ec_key)
{
    int retval = 0;
    const EC_GROUP *group;
    const BIGNUM *k = NULL;
    BIGNUM *h = NULL, *x = NULL, *y = NULL;
    EC_POINT *C1 = NULL, *point = NULL;
    BN_CTX *ctx = NULL;
    size_t deep, from;
    unsigned char *buf = NULL, *ckey = NULL, C3[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *md_ctx = NULL;

    if (!outlen)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ARGUMENT);
        return retval;
    }

    if (!md) md = EVP_sm3();

    /*compute plain text length*/
    if (!out)
    {
        *outlen = in->c->length;
        return 1;
    }

    if (*outlen < (size_t)in->c->length)
    {
        *outlen = in->c->length;
        return retval;
    }

    /*verify digest*/
    if ((int)md->md_size != in->m->length)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_DIGEST);
        return retval;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        return retval;
    }

    deep = (EC_GROUP_get_degree(group) + 7) / 8;

    if ((ctx = BN_CTX_new()) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*BN_CTX_start(ctx);*/
    h = BN_new();
    if (h == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    if (!EC_GROUP_get_cofactor(group, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if ((k = EC_KEY_get0_private_key(ec_key)) == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto err;
    }

    /*GET C1*/
    x = ASN1_INTEGER_to_BN(in->x, NULL);
    y = ASN1_INTEGER_to_BN(in->y, NULL);
    if (!x || !y)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
        goto err;
    }

    C1 = EC_POINT_new(group);
    point = EC_POINT_new(group);
    if ((C1 == NULL) || (point == NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_set_affine_coordinates_GFp(group, C1, x, y, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        /* NID_X9_62_characteristic_two_field */
        if (!EC_POINT_set_affine_coordinates_GF2m(group, C1, x, y, ctx))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    /*DETECT C1 is on this curve*/
    /*this is not need, because function EC_POINT_oct2point was do it*/
    if (!EC_POINT_is_on_curve(group, C1, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ARGUMENT);
        goto err;
    }

    /*DETECT [h]C1 is at infinity*/
    if (!EC_POINT_mul(group, point, NULL, C1, h, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (EC_POINT_is_at_infinity(group, point))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*COMPUTE [d]C1 into point*/
    if (!EC_POINT_mul(group, point, NULL, C1, k, ctx))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*OK, Now Compute t*/
    from = deep * 2 + 1;
    buf = OPENSSL_malloc(from + 10);
    if (buf == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    from = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, from + 10, ctx);
    if (!from)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    ckey = OPENSSL_malloc(in->c->length + 10);
    if (ckey == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (!KDF_GMT003_2012(ckey, in->c->length, (const unsigned char *)(buf + 1), from - 1, NULL, 0, md))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    /*GET PLAIN TEXT, cipher text format is: C1 + C3 + C2*/
    for (from = 0; from < (size_t)in->c->length; from++)
    {
        ckey[from] ^= in->c->data[from];
    }

    /*COMPUTE DIGEST*/
    md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_DigestInit(md_ctx, md);
    EVP_DigestUpdate(md_ctx, buf + 1, deep);
    EVP_DigestUpdate(md_ctx, ckey, in->c->length);
    EVP_DigestUpdate(md_ctx, buf + 1 + deep, deep);
    EVP_DigestFinal(md_ctx, C3, NULL);
    EVP_MD_CTX_destroy(md_ctx);

    /*cipher text format is: C1 + C3 + C2*/
    if (memcmp(C3, in->m->data, in->m->length))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
        goto err;
    }

    /*OK, SM2 Decrypt Successed*/
    memcpy(out, ckey, in->c->length);
    *outlen = in->c->length;

    retval = 1;
err:
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (h) BN_free(h);
    if (C1) EC_POINT_free(C1);
    if (point) EC_POINT_free(point);
    if (buf) OPENSSL_free(buf);
    if (ckey) OPENSSL_free(ckey);
    if (ctx)
    {
        /*BN_CTX_end(ctx);*/
        BN_CTX_free(ctx);
    }

    return retval;
}

/* Convert SM2 Cipher Structure to charactor string */
int i2c_sm2_enc(const SM2ENC *sm2enc, unsigned char **out)
{
    int retval = 0;
    unsigned char *ot;
    int outlen;

    if ((sm2enc->x->length > 0x20) || (sm2enc->y->length > 0x20))
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CURVE);
        goto err;
    }

    /* NOW OUTPUT THE SM2 ENC DATA FORMAT C1C3C2 */
    outlen = 1 + /*sm2enc->x->length + sm2enc->y->length*/ 0x20 + 0x20 + sm2enc->m->length + sm2enc->c->length;
    if (!out)
    {
        retval = outlen;
        goto err;
    }

    if (*out == NULL)
        *out = OPENSSL_malloc(outlen);
    if (*out == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ot = *out;
    *ot++ = 0x04;
    retval = 1;
    memset(ot, 0, 0x40);
    memcpy(ot + 0x20 - sm2enc->x->length, sm2enc->x->data, sm2enc->x->length);
    retval += /*sm2enc->x->length*/0x20;
    ot += /*sm2enc->x->length*/0x20;

    memcpy(ot + 0x20 - sm2enc->y->length, sm2enc->y->data, sm2enc->y->length);
    retval += /*sm2enc->y->length*/0x20;
    ot += /*sm2enc->y->length*/0x20;

    memcpy(ot, sm2enc->m->data, sm2enc->m->length);
    retval += sm2enc->m->length;
    ot += sm2enc->m->length;

    memcpy(ot, sm2enc->c->data, sm2enc->c->length);
    retval += sm2enc->c->length;

err:
    return retval;
}

/* Convert SM2 Cipher charactor string to Structure */
SM2ENC *c2i_sm2_enc(const unsigned char *in, size_t inlen, int md_size)
{
    /* IN FORMART MUST PC + X + Y + M + C, C1C3C2 */
    const unsigned char *p;
    SM2ENC *sm2enc = NULL;
    size_t len;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int ok = 0;

    /*DETECT input is correct*/
    len = 1 + 0x40 + md_size;
    if (inlen <= len)
    {
        /*invalid input parameters*/
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHER_TEXT);
        return NULL;
    }

    sm2enc = SM2ENC_new();
    if (!sm2enc)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* SET sm2enc->m */
    p = (const unsigned char *)(in + 1 + 0x40);
    if (!ASN1_OCTET_STRING_set(sm2enc->m, p, md_size))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
        goto err;
    }

    /* SET sm2enc->c */
    p = (const unsigned char *)(in + len);
    len = inlen - len;

    if (!ASN1_OCTET_STRING_set(sm2enc->c, p, len))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
        goto err;
    }

    /* SET sm2enc->x sm2enc->y */
    p = in;
    len = 0x41;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!group)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    point = EC_POINT_new((const EC_GROUP *)group);
    if (!point)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_oct2point((const EC_GROUP *)group, point, p, len, NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    x = BN_new();
    y = BN_new();
    if (!x || !y)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates_GFp((const EC_GROUP *)group, (const EC_POINT *)point, x, y, NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    if (!BN_to_ASN1_INTEGER((const BIGNUM *)x, sm2enc->x) || !BN_to_ASN1_INTEGER((const BIGNUM *)y, sm2enc->y))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
        goto err;
    }
    
    ok = 1;

err:
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (point) EC_POINT_free(point);
    if (group) EC_GROUP_free(group);
    if (!ok)
    {
        if (sm2enc)
        {
            SM2ENC_free(sm2enc);
            sm2enc = NULL;
        }
    }

    return sm2enc;
}

/* Convert EC Cipher Structure to charactor string */
int i2c_ec_enc(const SM2ENC *ec_enc, int curve_name, unsigned char **out)
{
    int retval = 0;
    unsigned char *ot;
    int outlen;
    EC_GROUP *group = NULL;
    int deep;

    /*First: get group*/
    group = EC_GROUP_new_by_curve_name(curve_name);
    if (!group)
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_EC_GROUP_NEW_BY_NAME_FAILURE);
        goto err;
    }

    deep = (EC_GROUP_get_degree(group) + 7) / 8;

    if ((ec_enc->x->length > deep) || (ec_enc->y->length > deep))
    {
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CURVE);
        goto err;
    }

    /* NOW OUTPUT THE EC ENC DATA FORMAT C1C3C2 */
    outlen = 1 + 2 * deep + ec_enc->m->length + ec_enc->c->length;
    if (!out)
    {
        retval = outlen;
        goto err;
    }

    if (*out == NULL)
        *out = OPENSSL_malloc(outlen);
    if (*out == NULL)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ot = *out;
    *ot++ = 0x04;
    retval = 1;
    memset(ot, 0, 2 * deep);
    memcpy(ot + deep - ec_enc->x->length, ec_enc->x->data, ec_enc->x->length);
    retval += deep;
    ot += deep;

    memcpy(ot + deep - ec_enc->y->length, ec_enc->y->data, ec_enc->y->length);
    retval += deep;
    ot += deep;

    memcpy(ot, ec_enc->m->data, ec_enc->m->length);
    retval += ec_enc->m->length;
    ot += ec_enc->m->length;

    memcpy(ot, ec_enc->c->data, ec_enc->c->length);
    retval += ec_enc->c->length;

err:
    if (group) EC_GROUP_free(group);

    return retval;
}

/* Convert EC Cipher charactor string to Structure */
SM2ENC *c2i_ec_enc(const unsigned char *in, size_t inlen, int curve_name, int md_size)
{
    /* IN FORMART MUST PC + X + Y + M + C, C1C3C2 */
    const unsigned char *p;
    SM2ENC *ec_enc = NULL;
    size_t len;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int deep;
    int ok = 0;

    group = EC_GROUP_new_by_curve_name(curve_name);
    if (!group)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    deep = (EC_GROUP_get_degree(group) + 7) / 8;

    /*DETECT input is correct*/
    len = 1 + 2 * deep + md_size;
    if (inlen <= len)
    {
        /*invalid input parameters*/
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHER_TEXT);
        return NULL;
    }

    ec_enc = SM2ENC_new();
    if (!ec_enc)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* SET ec_enc->m */
    p = (const unsigned char *)(in + len - md_size);
    if (!ASN1_OCTET_STRING_set(ec_enc->m, p, md_size))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
        goto err;
    }

    /* SET ec_enc->c */
    p = (const unsigned char *)(in + len);
    len = inlen - len;

    if (!ASN1_OCTET_STRING_set(ec_enc->c, p, len))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
        goto err;
    }

    /* SET ec_enc->x ec_enc->y */
    p = in;
    len = 1 + 2 * deep;

    point = EC_POINT_new((const EC_GROUP *)group);
    if (!point)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_oct2point((const EC_GROUP *)group, point, p, len, NULL))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
        goto err;
    }

    x = BN_new();
    y = BN_new();
    if (!x || !y)
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp((const EC_GROUP *)group, (const EC_POINT *)point, x, y, NULL))
        {
            OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        /* NID_X9_62_characteristic_two_field */
        if (!EC_POINT_get_affine_coordinates_GF2m((const EC_GROUP *)group, (const EC_POINT *)point, x, y, NULL))
        {
            SM2err(SM2_F_EC_CIPHER2STRUCTURE, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    if (!BN_to_ASN1_INTEGER((const BIGNUM *)x, ec_enc->x) || !BN_to_ASN1_INTEGER((const BIGNUM *)y, ec_enc->y))
    {
        OPENSSL_PUT_ERROR(SM2, ERR_R_ASN1_LIB);
        goto err;
    }

    ok = 1;

err:
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (point) EC_POINT_free(point);
    if (group) EC_GROUP_free(group);
    if (!ok)
    {
        if (ec_enc)
        {
            SM2ENC_free(ec_enc);
            ec_enc = NULL;
        }
    }

    return ec_enc;
}


static int SM2_enc_init(SM2_enc_ctx *pctx, EC_KEY *eckey) {
  RAND_seed((void *)"haha", 4);
  BN_CTX *bn_ctx = NULL;
  BIGNUM *order = NULL, *k = NULL, *h = NULL, *x = NULL, *y = NULL;
  const EC_GROUP *group = NULL;
  EC_POINT *Pb = NULL, *pS = NULL;
  const EC_POINT *ptmp = NULL;
  int nret = 0, nlen = 0;

  memset(pctx, 0, sizeof *pctx);
  pctx->dwct = 1;
  pctx->ncachelen = 0;

  if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL) {
    return 0;
  }
  bn_ctx = BN_CTX_new();
  order = BN_new();
  k = BN_new();
  h = BN_new();
  x = BN_new();
  y = BN_new();
  if (!bn_ctx || !order || !k || !h || !x || !y) {
    goto err;
  }
  if ((Pb = EC_POINT_new(group)) == NULL ||
      (pS = EC_POINT_new(group)) == NULL) {
    goto err;
  }
  if (!EC_GROUP_get_order(group, order, bn_ctx)) {
    goto err;
  }
  do {
    if (!BN_rand_range(k, order)) {
      goto err;
    }
  } while (BN_is_zero(k));
  if (!EC_POINT_mul(group, pS, k, NULL, NULL, bn_ctx)) {
    goto err;
  }
  if (!EC_POINT_get_affine_coordinates_GFp(group, pS, x, y, bn_ctx)) {
    goto err;
  }
  if (!EC_POINT_is_on_curve(group, pS, bn_ctx))
    goto err;

  pctx->bykG04xy[0] = 0x04;
  nlen = BN_num_bytes(x);
  if (32 < nlen)
    goto err;
  if (!BN_bn2bin(x, &(pctx->bykG04xy[1 + 32 - nlen]))) {
    goto err;
  }
  nlen = BN_num_bytes(y);
  if (32 < nlen)
    goto err;
  if (!BN_bn2bin(y, &(pctx->bykG04xy[33 + 32 - nlen]))) {
    goto err;
  }

  if (!EC_GROUP_get_cofactor(group, h, bn_ctx)) {
    goto err;
  }
  if ((ptmp = EC_KEY_get0_public_key(eckey)) == NULL) {
    goto err;
  }

  if (!EC_POINT_mul(group, pS, NULL, ptmp, h, bn_ctx)) {
    goto err;
  }
  if (EC_POINT_is_at_infinity(group, pS)) {
    goto err;
  }

  if (!EC_POINT_mul(group, pS, NULL, ptmp, k, bn_ctx)) {
    goto err;
  }
  if (!EC_POINT_get_affine_coordinates_GFp(group, pS, x, y, bn_ctx)) {
    goto err;
  }
  nlen = BN_num_bytes(x);
  if (nlen > 32)
    goto err;
  if (!BN_bn2bin(x, &(pctx->bykPbxy[32 - nlen]))) {
    goto err;
  }
  nlen = BN_num_bytes(y);
  if (nlen > 32)
    goto err;
  if (!BN_bn2bin(y, &(pctx->bykPbxy[32 + 32 - nlen]))) {
    goto err;
  }

  SM3_Init(&(pctx->c3sm3));
  SM3_Update(&(pctx->c3sm3), pctx->bykPbxy, 32);
  nret = 1;
err:
  if (bn_ctx)
    BN_CTX_free(bn_ctx);
  if (order)
    BN_free(order);
  if (k)
    BN_free(k);
  if (h)
    BN_free(h);
  if (x)
    BN_free(x);
  if (y)
    BN_free(y);
  if (Pb)
    EC_POINT_free(Pb);
  if (pS)
    EC_POINT_free(pS);
  return nret;
}

static void dwordtobyte(uint32_t dwvalue, uint8_t *bybuf) {
  int i = 0;
  for (; i < 4; i++) {
    bybuf[i] = (uint8_t)(dwvalue >> (8 * (3 - i)));
  }
}

static int x9_63_kdf(uint32_t *counter, const uint8_t *share, size_t sharelen,
              size_t keylen, uint8_t *outkey) {
  int ret = 0;

  SM3_CTX ctx;
  // unsigned char counter[4] = {0, 0, 0, 1};
  uint8_t bycounter[8] = {0};
  unsigned char dgst[EVP_MAX_MD_SIZE];
  int dgstlen;
  int rlen = (int)keylen;
  unsigned char *pp;

  pp = outkey;

  if (keylen > 32 * 0xffffff) {
    goto end;
  }

  while (rlen > 0) {
    dwordtobyte(*counter, bycounter);
    SM3_Init(&ctx);

    if (!SM3_Update(&ctx, share, sharelen)) {
      goto end;
    }
    if (!SM3_Update(&ctx, bycounter, 4)) {
      goto end;
    }
    dgstlen = 32;
    if (!SM3_Final(dgst, &ctx)) {
      goto end;
    }

    memcpy(pp, dgst, rlen >= dgstlen ? dgstlen : rlen);

    rlen -= dgstlen;
    pp += dgstlen;
    *counter += 1;
  }

  ret = 1;

end:
  return ret;
}

static int SM2_CMC_update(SM2_enc_ctx *pctx, const uint8_t *pbdata, size_t ndatalen,
                   uint8_t *pbCdata, size_t *pndatalen) {
  int nret = 0;
  int nnum, nr32;
  size_t nindex;
  uint8_t bybuf[64] = {0};
  int i = 0, n32 = 0;
  nindex = pctx->ncachelen;
  if (nindex > 0)
    memcpy(bybuf, pctx->bybuf, nindex);
  memcpy(bybuf + nindex, pbdata, 32 - nindex);
  nindex = 32 - nindex;

  nnum = pctx->ncachelen + ndatalen;
  pctx->ncachelen = nnum % 32;
  if (pctx->ncachelen > 0)
    memcpy(pctx->bybuf, pbdata + ndatalen - pctx->ncachelen, pctx->ncachelen);
  nr32 = nnum / 32;
  uint8_t byt[32] = {0}, byzero[32] = {0};
  for (i = 0; i < nr32; i++) {
    x9_63_kdf(&(pctx->dwct), pctx->bykPbxy, 64, 32, byt);
    if (0 == memcmp(byt, byzero, 32)) {
      goto err;
    }
    for (n32 = 0; n32 < 32; n32++) {
      pbCdata[*pndatalen] = bybuf[n32] ^ byt[n32];
      *pndatalen += 1;
    }
    if (32 == pctx->nc3len)  // dec
    {
      SM3_Update(&(pctx->c3sm3), pbCdata + *pndatalen - 32, 32);
    } else {
      SM3_Update(&(pctx->c3sm3), bybuf, 32);
    }
    if (nindex + 32 <= ndatalen) {
      memcpy(bybuf, pbdata + nindex, 32);
      nindex += 32;
    }
  }
  nret = 1;
err:
  return nret;
}


static int SM2_enc_update(SM2_enc_ctx *pctx, const uint8_t *pbdata, size_t ndatalen,
                   uint8_t *pbCdata, size_t *pndatalen) {
  int nret = 0;
  if (NULL == pctx || NULL == pndatalen || NULL == pbdata || 0 >= ndatalen)
    return 0;
  if (NULL == pbCdata) {
    *pndatalen = 65 + ndatalen;
    return 1;
  }
  if (*pndatalen < 65 + ndatalen) {
    *pndatalen = 65 + ndatalen;
    return 0;
  }
  //int nnum/*, nremain*/;
  //nnum = pctx->ncachelen + ndatalen;
  //nremain = nnum % 32;

  *pndatalen = 0;
  if (pctx->ncachelen + ndatalen < 32) {
    memcpy(pctx->bybuf + pctx->ncachelen, pbdata, ndatalen);
    pctx->ncachelen = pctx->ncachelen + ndatalen;
    return 1;
  }

  if (1 == pctx->dwct) {
    *pndatalen = 65;
    memcpy(pbCdata, pctx->bykG04xy, *pndatalen);
  }
  if (!SM2_CMC_update(pctx, pbdata, ndatalen, pbCdata, pndatalen))
    goto err;
  nret = 1;
err:
  return nret;
}

static int SM2_enc_final(SM2_enc_ctx *pctx, uint8_t *pbCdata, size_t *pndatalen) {
  if (NULL == pctx || NULL == pndatalen)
    return 0;
  int n32 = 0;
  size_t reqlen = pctx->ncachelen + 32;
  if (1 == pctx->dwct)
    reqlen += 65;
  if (NULL == pbCdata) {
    *pndatalen = reqlen;
    return 1;
  }
  if (*pndatalen < reqlen) {
    *pndatalen = reqlen;
    return 0;
  }
  uint8_t byc3[32] = {0};
  int nret = 0;
  *pndatalen = 0;
  if (1 == pctx->dwct) {
    *pndatalen = 65;
    memcpy(pbCdata, pctx->bykG04xy, *pndatalen);
  }
  if (pctx->ncachelen > 0) {
    uint8_t byt[32] = {0}, byzero[32] = {0};
    x9_63_kdf(&(pctx->dwct), pctx->bykPbxy, 64, 32, byt);
    if (0 == memcmp(byt, byzero, 32)) {
      goto err;
    }
    for (n32 = 0; n32 < pctx->ncachelen; n32++) {
      pbCdata[*pndatalen] = pctx->bybuf[n32] ^ byt[n32];
      *pndatalen += 1;
    }
    SM3_Update(&(pctx->c3sm3), pctx->bybuf, pctx->ncachelen);
  }
  SM3_Update(&(pctx->c3sm3), pctx->bykPbxy + 32, 32);
  SM3_Final(byc3, &(pctx->c3sm3));
  memcpy(pbCdata + *pndatalen, byc3, 32);
  *pndatalen += 32;
  nret = 1;
err:
  return nret;
}

int SM2_ENC(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen,
            uint8_t *pbCdata, size_t *pndatalen) {
  if (NULL == eckey || NULL == pbdata || NULL == pndatalen)
    return 0;
  if (NULL == pbCdata) {
    *pndatalen = 97 + ndatalen;
    return 1;
  }
  //uint8_t *p = NULL;
  size_t nlen = 0, ntmp = 0;
  int nret = 0;
  SM2_enc_ctx ctx;
  int nretry = 10;
  // t_kdf_zero_retry:
  nretry--;
  if (!SM2_enc_init(&ctx, eckey))
    goto err;
  //p = pbCdata;
  nlen = *pndatalen;
  ntmp = *pndatalen;
  if (!SM2_enc_update(&ctx, pbdata, ndatalen, pbCdata, &nlen)) {
    if (nretry <= 0)
      goto err;
  }
  *pndatalen = nlen;
  nlen = ntmp - *pndatalen;
  if (!SM2_enc_final(&ctx, pbCdata + *pndatalen, &nlen)) {
    if (nretry <= 0)
      goto err;
  }
  *pndatalen += nlen;
  nret = 1;
err:
  return nret;
}


int SM2_ENC_GMT(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen,
                uint8_t *pbCdata, size_t *pndatalen, int nformat) {
  int ok = 0;
  int nlen = 0, nindex = 0;
  size_t size = 0;
  uint8_t *p = 0, *ptmp = 0;
  SM2_CIPHERT_2012 *sm2ct = NULL;
  BIGNUM *bn = NULL;
  if (NULL == eckey || NULL == pbdata || NULL == pndatalen)
    return 0;
  if (NULL == pbCdata) {
    SM2_ENC(eckey, pbdata, ndatalen, NULL, &size);
    size += 12;  // 30820000 0200 0200 0400
    *pndatalen = size;
    return 1;
  }
  if (ndatalen > 65535) {  // too large data
    goto err;
  }
  nlen = ndatalen + 512;
  p = (uint8_t *)OPENSSL_malloc(nlen);
  if (!p) {
    goto err;
  }
  sm2ct = SM2_CIPHERT_2012_new();
  if (!sm2ct) {
    goto err;
  }
  size = nlen;
  if (!SM2_ENC(eckey, pbdata, ndatalen, p, &size)) {
    goto err;
  }
  nlen = (int)size;
  nindex = 1;
  bn = BN_bin2bn(p + nindex, 32, bn);
  sm2ct->x = BN_to_ASN1_INTEGER(bn, sm2ct->x);
  BN_zero(bn);
  nindex += 32;
  bn = BN_bin2bn(p + nindex, 32, bn);
  sm2ct->y = BN_to_ASN1_INTEGER(bn, sm2ct->y);
  nindex += 32;
  ASN1_OCTET_STRING_set(sm2ct->ct, p + nindex, nlen - nindex - 32);
  nindex = nlen - 32;
  ASN1_OCTET_STRING_set(sm2ct->hash, p + nindex, 32);
  nindex += 32;
  ptmp = pbCdata;
  if (!(nlen = i2d_SM2_CIPHERT_2012(sm2ct, &ptmp))) {
    goto err;
  }
  *pndatalen = nlen;
  ok = 1;
err:
  if (p) {
    OPENSSL_free(p);
  }
  if (bn) {
    BN_free(bn);
  }
  return ok;
}

#endif // OPENSSL_NO_GMTLS