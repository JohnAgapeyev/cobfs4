#ifndef COBFS4_MAIN_HEADER
#define COBFS4_MAIN_HEADER

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

unsigned char *elligator2(EVP_PKEY *pkey) {
    BIGNUM *r;
    BIGNUM *x;
    BIGNUM *y;
    unsigned long A;
    unsigned long u;
    BIGNUM *p;
    BIGNUM *tmp;
    BIGNUM *tmp2;
    BIGNUM *neg_one;
    BN_CTX *bnctx;
    unsigned char *skey;
    size_t skeylen;
    EVP_PKEY_CTX *pctx;

    A = 486662;
    u = 2;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    x = BN_new();
    y = BN_new();
    p = BN_new();
    r = BN_new();
    neg_one = BN_new();
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

    EVP_PKEY_get_raw_public_key(pkey, NULL, &skeylen);

    skey = OPENSSL_malloc(skeylen);

    EVP_PKEY_get_raw_public_key(pkey, skey, &skeylen);

    BN_bin2bn(skey, skeylen, x);

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
        return NULL;
    }

    /* tmp = -u*x*(x+A) */
    BN_set_word(tmp, A);
    BN_add(tmp, x, tmp);
    BN_mod_mul(tmp, tmp, x, p, bnctx);
    BN_mul_word(tmp, u);
    BN_mod_mul(tmp, tmp, neg_one, p, bnctx);

    /* tmp2 = (p-1)/2 */
    BN_copy(tmp2, p);
    BN_sub(tmp2, tmp2, BN_value_one());
    BN_rshift1(tmp2, tmp2);

    /* (-ux(x + A))**((p-1)/2) */
    BN_mod_exp(tmp, tmp, tmp2, p, bnctx);

    if (!BN_is_one(tmp)) {
        /* Precondition failed */
        return NULL;
    }

    /* y = y**2 = x**3 + Ax**2 + x */
    BN_mod_sqr(tmp, x, p, bnctx);
    BN_mod_mul(tmp, tmp, x, p, bnctx);
    BN_mod_add(tmp, tmp, x, p, bnctx);
    BN_mod_sqr(y, x, p, bnctx);
    BN_mul_word(y, A);
    BN_mod_add(y, y, tmp, p, bnctx);

    /* tmp = (p-3)/8 */
    BN_copy(tmp, p);
    BN_sub_word(tmp, 3);
    BN_rshift(tmp, tmp, 3);

    /* y = sqrt(y**2)*/
    BN_mod_exp(y, y, tmp, p, bnctx);

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
        BN_mul(r, r, neg_one, bnctx);

        BN_copy(tmp, x);
        BN_mul_word(tmp, u);

        /* BN_div(r, NULL, r, tmp, bnctx); */
        BN_mod_inverse(tmp, tmp, p, bnctx);
        BN_mod_mul(r, r, tmp, p, bnctx);

        /* tmp = (q-3)/8 */
        BN_copy(tmp, p);
        BN_sub_word(tmp, 3);
        BN_rshift(tmp, tmp, 3);

        BN_mod_exp(r, r, tmp, p, bnctx);
    } else {
        /* y is element of sqrt(Fq) */
        BN_copy(r, x);
        BN_add_word(r, A);
        BN_mul_word(r, u);
        BN_mul(tmp, x, neg_one, bnctx);

        /* BN_div(r, NULL, r, tmp, bnctx); */
        BN_mod_inverse(tmp, tmp, p, bnctx);
        BN_mod_mul(r, r, tmp, p, bnctx);

        /* tmp = (q-3)/8 */
        BN_copy(tmp, p);
        BN_sub_word(tmp, 3);
        BN_rshift(tmp, tmp, 3);

        BN_mod_exp(r, r, tmp, p, bnctx);
    }

    BN_bn2bin(r, skey);

    EVP_PKEY_CTX_free(pctx);

    return skey;
}

EVP_PKEY *elligator2_inv(unsigned char *buffer, size_t len) {
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
    BN_CTX *bnctx;
    unsigned char *skey;
    size_t skeylen;
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey;
    size_t i;

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
    tmp = BN_new();
    tmp2 = BN_new();
    bnctx = BN_CTX_new();
    pkey = EVP_PKEY_new();

    /* p = (2**255)-19 */
    BN_set_word(p, 2);
    BN_set_word(tmp, 255);
    BN_exp(p, p, tmp, bnctx);
    BN_sub_word(p, 19);

    BN_zero(neg_one);
    BN_sub_word(neg_one, 1);

    BN_bin2bn(buffer, len, r);

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
        return NULL;
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
        return NULL;
    }

    /* v = -A/(1+ur**2) */
    BN_set_word(tmp, A);
    BN_mul(tmp, tmp, neg_one, bnctx);
    BN_mod_sqr(v, r, p, bnctx);
    BN_mul_word(v, u);
    BN_add_word(v, 1);

    /* BN_div(v, NULL, tmp, v, bnctx); */
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

    BN_copy(tmp, p);
    BN_sub_word(tmp, 3);
    BN_rshift(tmp, tmp, 3);

    BN_mod_exp(y, y, tmp, p, bnctx);
    BN_mod_mul(y, y, e, p, bnctx);
    BN_mod_mul(y, y, neg_one, p, bnctx);


    skeylen = BN_num_bytes(x);
    skey = OPENSSL_malloc(BN_num_bytes(x));

    BN_bn2bin(x, skey);

    BN_print_fp(stdout, x);
    printf("\n");
    BN_print_fp(stdout, y);
    printf("\n");

#if 0
    for (i = 0; i < 32; ++i) {
        printf("%02x", skey[i]);
    }
    printf("\n");
#endif

    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, skey, skeylen);

    return pkey;
}

void test_elligator(void) {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey, *peerkey;
    size_t skeylen;
    unsigned char *skey;
    unsigned char *skey2;
    unsigned char *skey3;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    BIGNUM *bnp;
    BN_CTX *bnctx;
    size_t i;

    bnp = BN_new();
    bnctx = BN_CTX_new();

    pkey = EVP_PKEY_new();
    peerkey = EVP_PKEY_new();

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    skey3 = elligator2(pkey);

    if (skey3) {
        for (i = 0; i < 32; ++i) {
            printf("%02x", skey3[i]);
        }
        printf("\n");
        elligator2_inv(skey3, 32);
    } else {
        printf("Generated key was not valid for elligator2\n");
    }

    skey3 = OPENSSL_malloc(1024);

    EVP_PKEY_get_raw_public_key(pkey, skey3, &skeylen);
    BN_bin2bn(skey3, skeylen, bnp);
    BN_bn2bin(bnp, skey3);
    peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, skey3, skeylen);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peerkey);

    EVP_PKEY_derive(ctx, NULL, &skeylen);

    skey = OPENSSL_malloc(skeylen);

    EVP_PKEY_derive(ctx, skey, &skeylen);

#if 0
    for (i = 0; i < skeylen; ++i) {
        printf("%02x", skey[i]);
    }
    printf("\n");
#endif

}

#if defined(__cplusplus)
}
#endif

#endif /* COBFS4_MAIN_HEADER */
