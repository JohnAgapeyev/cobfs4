#ifndef COBFS4_MAIN_HEADER
#define COBFS4_MAIN_HEADER

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>
#include <sodium.h>

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

#if defined(__cplusplus)
}
#endif

#endif /* COBFS4_MAIN_HEADER */
