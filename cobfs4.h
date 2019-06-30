#ifndef COBFS4_MAIN_HEADER
#define COBFS4_MAIN_HEADER

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#if 0
void elligator2(unsigned char in_point[crypto_core_ed25519_BYTES],
        unsigned char out_point[crypto_core_ed25519_UNIFORMBYTES]) {
    const unsigned int A = 486662;

    unsigned char p[crypto_core_ed25519_SCALARBYTES];
    const char *p_str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
    unsigned int i;
    unsigned char tmp;
    unsigned char s[crypto_core_ed25519_SCALARBYTES];

    if (sodium_hex2bin(p, sizeof(p), p_str, strlen(p_str), NULL, NULL, NULL)) {
        /* Could not convert hardcoded hex string to binary */
        abort();
    }

    for (i = 0; i < (crypto_core_ed25519_BYTES / 2); ++i) {
        tmp = p[i];
        p[i] = p[crypto_core_ed25519_BYTES - i - 1];
        p[crypto_core_ed25519_BYTES - i - 1] = tmp;
    }

    for (i = 0; i < crypto_core_ed25519_BYTES; ++i) {
        printf("%02x", p[i]);
    }
    printf("\n");

    for (i = 0; i < crypto_core_ed25519_SCALARBYTES; ++i) {
        printf("%02x", s[i]);
    }
    printf("\n");

}

void elligator2_inv(unsigned char in_point[crypto_core_ed25519_UNIFORMBYTES],
        unsigned char out_point[crypto_core_ed25519_BYTES]) {
    crypto_core_ed25519_from_uniform(out_point, in_point);
}

void test_elligator(void) {
    unsigned char x[crypto_core_ed25519_BYTES];
    unsigned char y[crypto_core_ed25519_UNIFORMBYTES];
    unsigned char z[crypto_core_ed25519_BYTES];

    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
        abort();
    }

    crypto_core_ed25519_random(x);
    elligator2(x, y);
    elligator2_inv(y, z);

    if (memcmp(x, z, crypto_core_ed25519_BYTES) != 0) {
        fprintf(stderr, "Mapping failed to invert properly!\n");
    } else {
        fprintf(stdout, "Mapping was able to invert correctly\n");
    }
}
#else

unsigned char *elligator2(EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx;
    BIGNUM *r;
    BIGNUM *A;
    BIGNUM *p;
    BIGNUM *tmp;
    BIGNUM *u1;
    BIGNUM *u2;
    BIGNUM *w1;
    BIGNUM *n;
    BN_CTX *bnctx;
    unsigned char *skey;
    size_t skeylen;
    size_t i;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    r = BN_new();
    A = BN_new();
    p = BN_new();
    u1 = BN_new();
    u2 = BN_new();
    w1 = BN_new();
    n = BN_new();
    tmp = BN_new();
    bnctx = BN_CTX_new();

    BN_set_word(A, 486662);
    BN_set_word(n, 2);

    /* p = (2**255)-19 */
    BN_set_word(p, 2);
    BN_set_word(tmp, 255);
    BN_exp(p, p, tmp, bnctx);
    BN_set_word(tmp, 19);
    BN_sub(p, p, tmp);

    EVP_PKEY_get_raw_public_key(pkey, NULL, &skeylen);

    skey = OPENSSL_malloc(skeylen);

    EVP_PKEY_get_raw_public_key(pkey, skey, &skeylen);

    BN_bin2bn(skey, skeylen, r);

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
     *  - r = sqrt((-1/2)(u/u+A))
     * else
     *  - r = sqrt((-1/2)((u+A)/u))
    */

    /*
     u1 = -A * inv(1 + nr**2) (mod p)
    BN_copy(u1, r);
    BN_mod_sqr(u1, r, p, bnctx);
    BN_mod_mul(u1, u1, n, p, bnctx);
    BN_mod_add(u1, u1, BN_value_one(), p, bnctx);
    BN_mod_inverse(u1, u1, p, bnctx);
    BN_mod_mul(u1, u1, A, p, bnctx);
    */

    BN_bn2bin(r, skey);

    EVP_PKEY_CTX_free(pctx);

    return skey;
}

EVP_PKEY *elligator2_inv(unsigned char *buffer) {
    /*
     * Do all the math here
     * r is the raw buffer input
     * A is 486662
     * B is 1
     * p is (2**255)-19
     * u is 2
     * Preconditions:
     *  - 1 + ur**2 != 0
     *  - (A**2)u(r**2) != B((1 + ur**2)**2)
     *
     * Output is x (y can also be calculated, but is not necessary)
     * v = -A/(1+ur**2)
     * e = (v**3+Av**2+Bv)**((p-1)/2)
     * x = ev-(1-e)A/2
     * y = -e*sqrt(x**3+Ax**2+Bx)
    */
    return NULL;
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

    for (i = 0; i < skeylen; ++i) {
        printf("%02x", skey[i]);
    }
    printf("\n");

}
#endif

#if defined(__cplusplus)
}
#endif

#endif /* COBFS4_MAIN_HEADER */
