#ifndef COBFS4_MAIN_HEADER
#define COBFS4_MAIN_HEADER

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

unsigned char *elligator2(EVP_PKEY *pkey) {
    BIGNUM *r;
    BIGNUM *x;
    BIGNUM *y;
    unsigned long A;
    unsigned long u;
    BIGNUM *p;
    BIGNUM *p_minus_one;
    BIGNUM *tmp;
    BIGNUM *tmp2;
    BIGNUM *neg_one;
    BN_CTX *bnctx;
    unsigned char *skey;
    size_t skeylen;
    EVP_PKEY_CTX *pctx;
    unsigned char tc;
    size_t i;

    A = 486662;
    u = 2;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    x = BN_new();
    y = BN_new();
    p = BN_new();
    r = BN_new();
    neg_one = BN_new();
    p_minus_one = BN_new();
    tmp = BN_new();
    tmp2 = BN_new();
    bnctx = BN_CTX_new();

    EVP_PKEY_get_raw_public_key(pkey, NULL, &skeylen);
    skey = OPENSSL_malloc(skeylen);
    EVP_PKEY_get_raw_public_key(pkey, skey, &skeylen);

    /* p = (2**255)-19 */
    BN_set_word(p, 2);
    BN_set_word(tmp, 255);
    BN_exp(p, p, tmp, bnctx);
    BN_sub_word(p, 19);

    BN_zero(neg_one);
    BN_sub_word(neg_one, 1);

    BN_copy(p_minus_one, p);
    BN_sub_word(p_minus_one, 1);

    for (i = 0; i < skeylen / 2 ; ++i) {
        tc = skey[i];
        skey[i] = skey[skeylen - i - 1];
        skey[skeylen - i - 1] = tc;
    }

    BN_bin2bn(skey, skeylen, x);
    BN_mod(x, x, p, bnctx);

    /*
     * Do all the math here
     * x is the public key input
     * A is 486662
     * B is 1
     * p is (2**255)-19
     * u is 2
     * Preconditions:
     *  - x != -A
     *  - (-ux(x + A))**((p-1)/2) == 1
     *
     * Calculate y from curve equation:
     * y**2 = x**3 + Ax**2 + x
     *
     * Output is r
     * if y <= (p-1)/2
     *  - r = sqrt(-x/((x+A)u))
     * else
     *  - r = sqrt(-(x+A)/(ux))
    */

    BN_set_word(tmp, A);
    BN_mul(tmp, tmp, neg_one, bnctx);

    /* Check if x == -A */
    if (BN_cmp(x, tmp) == 0) {
        /* Precondition failed */
        goto error;
    }

    /* tmp = -u*x*(x+A) */
    BN_set_word(tmp, A);
    BN_mod_add(tmp, tmp, x, p, bnctx);
    BN_mod_mul(tmp, tmp, x, p, bnctx);
    BN_mul_word(tmp, u);
    BN_mod_mul(tmp, tmp, neg_one, p, bnctx);

    /* tmp2 = (p-1)/2 */
    BN_copy(tmp2, p);
    BN_sub_word(tmp2, 1);
    BN_rshift1(tmp2, tmp2);

    /* (-ux(x + A))**((p-1)/2) */
    BN_mod_exp(tmp, tmp, tmp2, p, bnctx);

    if (BN_cmp(tmp, p_minus_one) == 0) {
        BN_copy(tmp, neg_one);
    }

    if (!BN_is_one(tmp)) {
        /* Precondition failed */
        goto error;
    }

    /* y = y**2 = x**3 + Ax**2 + x */
    BN_mod_sqr(tmp, x, p, bnctx);
    BN_mod_mul(tmp, tmp, x, p, bnctx);
    BN_mod_add(tmp, tmp, x, p, bnctx);
    BN_mod_sqr(y, x, p, bnctx);
    BN_mul_word(y, A);
    BN_mod_add(y, y, tmp, p, bnctx);

    /* tmp2 = (p-1)/2 */
    BN_copy(tmp2, p);
    BN_sub_word(tmp2, 1);
    BN_rshift1(tmp2, tmp2);
    BN_mod_exp(tmp, y, tmp2, p, bnctx);

    if (!BN_is_one(tmp)) {
        /* y is not a square, this is an invalid point */
        goto error;
    }

    /* y = sqrt(y**2)*/
    BN_mod_sqrt(y, y, p, bnctx);

    if (BN_is_zero(y)) {
        /* Precondition failed */
        goto error;
    }

    /* tmp = (p-1)/2 */
    BN_copy(tmp, p);
    BN_sub_word(tmp, 1);
    BN_rshift1(tmp, tmp);

    /*
     * Output is r
     * if y <= (p-1)/2
     *  - r = sqrt(-x/((x+A)u))
     * else
     *  - r = sqrt(-(x+A)/(ux))
     */
    if (BN_cmp(y, tmp) == 1) {
        /* y is NOT element of sqrt(Fq) */
        BN_copy(r, x);
        BN_add_word(r, A);
        BN_mod_mul(r, r, neg_one, p, bnctx);

        BN_copy(tmp, x);
        BN_mul_word(tmp, u);

        BN_mod_inverse(tmp, tmp, p, bnctx);
        BN_mod_mul(r, r, tmp, p, bnctx);

        BN_mod_sqrt(r, r, p, bnctx);
    } else {
        /* y is element of sqrt(Fq) */
        BN_copy(r, x);
        BN_add_word(r, A);
        BN_mul_word(r, u);
        BN_mod_mul(tmp, x, neg_one, p, bnctx);

        BN_mod_inverse(r, r, p, bnctx);
        BN_mod_mul(r, r, tmp, p, bnctx);

        BN_mod_sqrt(r, r, p, bnctx);
    }

    memset(skey, 0, skeylen);
    BN_bn2bin(r, skey + (skeylen - BN_num_bytes(r)));

    BN_CTX_free(bnctx);
    BN_free(tmp2);
    BN_free(tmp);
    BN_free(p_minus_one);
    BN_free(neg_one);
    BN_free(r);
    BN_free(p);
    BN_free(y);
    BN_free(x);
    EVP_PKEY_CTX_free(pctx);

    return skey;

error:
    OPENSSL_free(skey);
free_bignum_ctx:
    BN_CTX_free(bnctx);
free_tmp2:
    BN_free(tmp2);
free_tmp:
    BN_free(tmp);
free_p_minus_one:
    BN_free(p_minus_one);
free_neg_one:
    BN_free(neg_one);
free_r:
    BN_free(r);
free_p:
    BN_free(p);
free_y:
    BN_free(y);
free_x:
    BN_free(x);
free_pkey_ctx:
    EVP_PKEY_CTX_free(pctx);

    return NULL;
}

EVP_PKEY *elligator2_inv(unsigned char buffer[32]) {
    BIGNUM *r;
    BIGNUM *v;
    BIGNUM *e;
    BIGNUM *x;
    BIGNUM *y;
    unsigned long A;
    unsigned long u;
    BIGNUM *p;
    BIGNUM *tmp;
    BIGNUM *tmp2;
    BIGNUM *neg_one;
    BIGNUM *p_minus_one;
    BN_CTX *bnctx;
    unsigned char *skey;
    size_t skeylen;
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey;
    size_t i;
    unsigned char tc;

    A = 486662;
    u = 2;
    skeylen = 32;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    v = BN_new();
    e = BN_new();
    x = BN_new();
    y = BN_new();
    p = BN_new();
    r = BN_new();
    neg_one = BN_new();
    p_minus_one = BN_new();
    tmp = BN_new();
    tmp2 = BN_new();
    bnctx = BN_CTX_new();

    /* p = (2**255)-19 */
    BN_set_word(p, 2);
    BN_set_word(tmp, 255);
    BN_exp(p, p, tmp, bnctx);
    BN_sub_word(p, 19);

    BN_zero(neg_one);
    BN_sub_word(neg_one, 1);

    BN_copy(p_minus_one, p);
    BN_sub_word(p_minus_one, 1);

    BN_bin2bn(buffer, 32, r);

    /*
     * Do all the math here
     * r is the raw buffer input
     * A is 486662
     * p is (2**255)-19
     * u is 2
     * Preconditions:
     *  - 1 + ur**2 != 0
     *  - (A**2)u(r**2) != (1 + ur**2)**2
     *
     * Output is x (y can also be calculated, but is not necessary)
     * v = -A/(1+ur**2)
     * e = (v**3+Av**2+v)**((p-1)/2)
     * x = ev-(1-e)A/2
     * y = -e*sqrt(x**3+Ax**2+x)
     */

    /* tmp = 1+ur**2 */
    BN_mod_sqr(tmp, r, p, bnctx);
    BN_mul_word(tmp, u);
    BN_add_word(tmp, 1);

    if (BN_is_zero(tmp)) {
        /* Precondition failed */
        goto error;
    }

    /* tmp2 = (1+ur**2)**2 */
    BN_mod_sqr(tmp2, tmp, p, bnctx);

    /* tmp = (A**2)u(r**2) */
    BN_mod_sqr(tmp, r, p, bnctx);
    BN_mul_word(tmp, u);
    BN_mul_word(tmp, A);
    BN_mul_word(tmp, A);
    BN_nnmod(tmp, tmp, p, bnctx);

    if (BN_cmp(tmp, tmp2) == 0) {
        /* Precondition failed */
        goto error;
    }

    /* v = -A/(1+ur**2) */
    BN_set_word(tmp, A);
    BN_mul(tmp, tmp, neg_one, bnctx);
    BN_mod_sqr(v, r, p, bnctx);
    BN_mul_word(v, u);
    BN_add_word(v, 1);

    BN_mod_inverse(v, v, p, bnctx);
    BN_mod_mul(v, tmp, v, p, bnctx);

    BN_mod(v, v, p, bnctx);

    /* e = (v**3+Av**2+v)**((p-1)/2) */
    BN_mod_sqr(e, v, p, bnctx);
    BN_mod_mul(e, e, v, p, bnctx);
    BN_mod_add(e, e, v, p, bnctx);
    BN_mod_sqr(tmp, v, p, bnctx);
    BN_mul_word(tmp, A);
    BN_mod_add(e, e, tmp, p, bnctx);

    BN_sub(tmp, p, BN_value_one());
    BN_rshift1(tmp, tmp);
    BN_mod_exp(e, e, tmp, p, bnctx);

    if (BN_cmp(e, p_minus_one) == 0) {
        BN_copy(e, neg_one);
    }

    /* x = ev-(1-e)A/2 */
    BN_set_word(tmp, 1);
    BN_sub(tmp, tmp, e);
    BN_mul_word(tmp, A);
    BN_rshift1(tmp, tmp);
    BN_mod_mul(x, e, v, p, bnctx);
    BN_mod_sub(x, x, tmp, p, bnctx);

    /* y = -e*sqrt(x**3+Ax**2+x) */
    BN_mod_sqr(y, x, p, bnctx);
    BN_mod_mul(y, y, x, p, bnctx);
    BN_mod_add(y, y, x, p, bnctx);
    BN_mod_sqr(tmp, x, p, bnctx);
    BN_mul_word(tmp, A);
    BN_mod_add(y, y, tmp, p, bnctx);

    BN_mod_sqrt(y, y, p, bnctx);

    BN_mod_mul(y, y, e, p, bnctx);
    BN_mod_mul(y, y, neg_one, p, bnctx);

    skey = OPENSSL_malloc(skeylen);

    memset(skey, 0, skeylen);
    BN_bn2bin(x, skey + (skeylen - BN_num_bytes(x)));

    for (i = 0; i < skeylen / 2 ; ++i) {
        tc = skey[i];
        skey[i] = skey[skeylen - i - 1];
        skey[skeylen - i - 1] = tc;
    }
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, skey, skeylen);

    OPENSSL_free(skey);

    BN_free(v);
    BN_free(e);
    BN_free(x);
    BN_free(y);
    BN_free(p);
    BN_free(r);
    BN_free(neg_one);
    BN_free(p_minus_one);
    BN_free(tmp);
    BN_free(tmp2);

    BN_CTX_free(bnctx);
    EVP_PKEY_CTX_free(pctx);

    return pkey;

error:
    BN_free(v);
    BN_free(e);
    BN_free(x);
    BN_free(y);
    BN_free(p);
    BN_free(r);
    BN_free(neg_one);
    BN_free(p_minus_one);
    BN_free(tmp);
    BN_free(tmp2);

    BN_CTX_free(bnctx);
    EVP_PKEY_CTX_free(pctx);

    return NULL;
}

void test_elligator(void) {
    EVP_PKEY *pkey;
    EVP_PKEY *peerkey;
    size_t skeylen;
    unsigned char *skey;
    unsigned char *skey2;
    unsigned char *skey3;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    BIGNUM *p;
    BIGNUM *tmp;
    BIGNUM *x;
    BN_CTX *bnctx;
    size_t i;

    p = BN_new();
    tmp = BN_new();
    x = BN_new();
    bnctx = BN_CTX_new();

    pkey = EVP_PKEY_new();

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);

    EVP_PKEY_get_raw_public_key(pkey, NULL, &skeylen);

    skey = OPENSSL_malloc(skeylen);
    skey2 = OPENSSL_malloc(skeylen);

    if (!EVP_PKEY_get_raw_public_key(pkey, skey, &skeylen)) {
        printf("Get raw call failed\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
    }

    skey3 = elligator2(pkey);

    if (skey3) {
        peerkey = elligator2_inv(skey3);
        if (peerkey) {
            if (!EVP_PKEY_get_raw_public_key(peerkey, skey2, &skeylen)) {
                printf("Get raw call failed\n");
                printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
            }
            for (i = 0; i < 32; ++i) {
                printf("%02x", skey[i]);
            }
            printf("\n");
            for (i = 0; i < 32; ++i) {
                printf("%02x", skey2[i]);
            }
            printf("\n");
            if (memcmp(skey, skey2, 32) == 0) {
                printf("Elligator works as intended\n");
            } else {
                printf("Elligator FAILED\n");
            }
            EVP_PKEY_free(peerkey);
        }
    } else {
        printf("Generated key was not valid for elligator2\n");
    }

    OPENSSL_free(skey);
    OPENSSL_free(skey2);
    OPENSSL_free(skey3);

    BN_free(p);
    BN_free(tmp);
    BN_free(x);

    BN_CTX_free(bnctx);

    EVP_PKEY_free(pkey);

    EVP_PKEY_CTX_free(pctx);
}

#if defined(__cplusplus)
}
#endif

#endif /* COBFS4_MAIN_HEADER */
