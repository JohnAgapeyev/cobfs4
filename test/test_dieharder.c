#include <openssl/rand.h>
#include <openssl/evp.h>

#include <string.h>

#include "cobfs4.h"
#include "test.h"
#include "random.h"
#include "constants.h"
#include "elligator.h"
#include "ecdh.h"

uint8_t seed[COBFS4_SECRET_KEY_LEN];
struct rng_state state;

unsigned int seeded_random(void) {
    unsigned int x;
    deterministic_random(&state, (uint8_t *) &x, sizeof(x));
    return x;
}

unsigned int elligator_random(void) {
    unsigned int x;
    static uint8_t elligator[COBFS4_ELLIGATOR_LEN];
    static size_t bytes_used = 0;

    if (bytes_used == 0) {
        EVP_PKEY_CTX *pctx = NULL;
        EVP_PKEY *key = NULL;
retry:
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        key = EVP_PKEY_new();
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &key);
        if (elligator2_inv(key, elligator) != COBFS4_OK) {
            EVP_PKEY_free(key);
            EVP_PKEY_CTX_free(pctx);
            goto retry;
        }
        EVP_PKEY_free(key);
        EVP_PKEY_CTX_free(pctx);
    }
    memcpy(&x, elligator + bytes_used, sizeof(x));
    bytes_used += sizeof(unsigned int);
    if (bytes_used >= COBFS4_ELLIGATOR_LEN) {
        bytes_used = 0;
    }
    return x;
}

int main(int argc, char **argv) {
    unsigned int x;
    if (argc != 2) {
        return EXIT_FAILURE;
    }
    if (argv[1][0] == 'r') {
        RAND_bytes((unsigned char *) &seed, sizeof(seed));
        seed_random(&state, seed);

        for (;;) {
            x = seeded_random();
            fwrite(&x, sizeof(x), 1, stdout);
        }
    } else {
        for (;;) {
            x = elligator_random();
            fwrite(&x, sizeof(x), 1, stdout);
        }
    }

    return 0;
}
