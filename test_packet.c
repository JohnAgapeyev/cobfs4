#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "packet.h"
#include "ecdh.h"
#include "ntor.h"

//Stand-in for a real digest, since the value doesn't matter at all
static const uint8_t *identity_digest = (const uint8_t *) "012345678901234567890123456789ab";

void test_handshake(void) {
    int good = 0;
    int bad = 0;
    int i = 0;
    for (i = 0; i < 10000; ++i) {
        EVP_PKEY *B = ecdh_key_alloc();
        EVP_PKEY *X = ecdh_key_alloc();
        EVP_PKEY *Y = ecdh_key_alloc();

        uint8_t client_tag[32];
        uint8_t client_seed[32];
        uint8_t server_tag[32];
        uint8_t server_seed[32];

        if (server_ntor(Y, B, X, identity_digest, server_tag, server_seed)) {
            ++bad;
            EVP_PKEY_free(B);
            EVP_PKEY_free(X);
            EVP_PKEY_free(Y);
            continue;
        }

        if (client_ntor(X, Y, B, identity_digest, client_tag, client_seed)) {
            ++bad;
            EVP_PKEY_free(B);
            EVP_PKEY_free(X);
            EVP_PKEY_free(Y);
            continue;
        }

        if (memcmp(server_tag, client_tag, 32) || memcmp(server_seed, client_seed, 32)) {
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
