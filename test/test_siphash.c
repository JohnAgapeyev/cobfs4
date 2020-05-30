#include <openssl/rand.h>

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "cobfs4.h"
#include "test.h"
#include "siphash.h"
#include "constants.h"

void test_siphash(void) {
    int good = 0;
    int bad = 0;
    int i;
    for (i = 0; i < TEST_CASE_COUNT; ++i) {
        uint8_t key[COBFS4_SIPHASH_KEY_LEN];
        uint8_t iv[COBFS4_SIPHASH_IV_LEN];

        uint16_t out1;
        uint16_t out2;

        uint16_t out3;
        uint16_t out4;

        struct siphash_ctx ctx1;
        struct siphash_ctx ctx2;

        RAND_bytes((unsigned char *) &key, sizeof(key));
        RAND_bytes((unsigned char *) &iv, sizeof(iv));

        siphash_init(&ctx1, key, iv);
        siphash_init(&ctx2, key, iv);

        if (siphash(&ctx1, &out1) == -1) {
            ++bad;
            continue;
        }

        if (siphash(&ctx1, &out2) == -1) {
            ++bad;
            continue;
        }

        if (siphash(&ctx2, &out3) == -1) {
            ++bad;
            continue;
        }

        if (siphash(&ctx2, &out4) == -1) {
            ++bad;
            continue;
        }

        if (out1 != out3) {
            ++bad;
            continue;
        }

        if (out2 != out4) {
            ++bad;
        } else {
            ++good;
        }
    }

    printf("Siphash testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
