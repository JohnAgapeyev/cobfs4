#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

#include "cobfs4.h"
#include "test.h"
#include "ecdh.h"

void test_ecdh(void) {
    int good = 0;
    int bad = 0;
    int i;
    for (i = 0; i < 10000; ++i) {
        EVP_PKEY *first_key = ecdh_key_alloc();
        EVP_PKEY *second_key = ecdh_key_alloc();
        unsigned char client_shared[32];
        unsigned char server_shared[32];

        if (ecdh_derive(first_key, second_key, client_shared)) {
            ++bad;
            EVP_PKEY_free(first_key);
            EVP_PKEY_free(second_key);
            continue;
        }

        if (ecdh_derive(second_key, first_key, server_shared)) {
            ++bad;
            EVP_PKEY_free(first_key);
            EVP_PKEY_free(second_key);
            continue;
        }

        if (memcmp(client_shared, server_shared, 32) == 0) {
            ++good;
        } else {
            ++bad;
        }

        EVP_PKEY_free(first_key);
        EVP_PKEY_free(second_key);
    }

    printf("ECDH testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
