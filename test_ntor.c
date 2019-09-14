#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "ntor.h"
#include "ecdh.h"

//Stand-in for a real digest, since the value doesn't matter at all
static const unsigned char *identity_digest = (const unsigned char *) "012345678901234567890123456789ab";

void test_ntor(void) {
    int good = 0;
    int bad = 0;
    int i = 0;
    for (i = 0; i < 10000; ++i) {
        EVP_PKEY *B = ecdh_key_alloc();
        EVP_PKEY *X = ecdh_key_alloc();
        EVP_PKEY *Y = ecdh_key_alloc();

        unsigned char client_tag[32];
        unsigned char server_tag[32];

        if (server_ntor(Y, B, X, identity_digest, server_tag)) {
            ++bad;
            EVP_PKEY_free(B);
            EVP_PKEY_free(X);
            EVP_PKEY_free(Y);
            continue;
        }

        if (client_ntor(X, Y, B, identity_digest, client_tag)) {
            ++bad;
            EVP_PKEY_free(B);
            EVP_PKEY_free(X);
            EVP_PKEY_free(Y);
            continue;
        }

        if (memcmp(server_tag, client_tag, 32)) {
            ++bad;
            EVP_PKEY_free(B);
            EVP_PKEY_free(X);
            EVP_PKEY_free(Y);
            continue;
        }

        ++good;
        EVP_PKEY_free(B);
        EVP_PKEY_free(X);
        EVP_PKEY_free(Y);
    }

    printf("Ntor testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
