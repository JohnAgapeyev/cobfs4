#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "ntor.h"
#include "ecdh.h"
#include "constants.h"

//Stand-in for a real digest, since the value doesn't matter at all
static const uint8_t *identity_digest = (const uint8_t *) "012345678901234567890123456789ab";

void test_ntor(void) {
    int good = 0;
    int bad = 0;
    int i = 0;
    for (i = 0; i < 10000; ++i) {
        EVP_PKEY *X = ecdh_key_alloc();
        EVP_PKEY *Y = ecdh_key_alloc();

        struct shared_data shared;
        shared.ntor = ecdh_key_alloc();
        memcpy(&shared.identity_digest, identity_digest, strlen((char *) identity_digest));

        struct ntor_output client;
        struct ntor_output server;

        if (server_ntor(Y, X, &shared, &server)) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(X);
            EVP_PKEY_free(Y);
            continue;
        }

        if (client_ntor(X, Y, &shared, &client)) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(X);
            EVP_PKEY_free(Y);
            continue;
        }

        if (memcmp(server.auth_tag, client.auth_tag, COBFS4_AUTH_LEN) || memcmp(server.key_seed, client.key_seed, COBFS4_SEED_LEN)) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(X);
            EVP_PKEY_free(Y);
            continue;
        }

        ++good;
        EVP_PKEY_free(shared.ntor);
        EVP_PKEY_free(X);
        EVP_PKEY_free(Y);
    }

    printf("Ntor testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
