#include <openssl/rand.h>

#include <string.h>

#include "cobfs4.h"
#include "test.h"
#include "random.h"
#include "constants.h"

void test_seeded_random(void) {
    int good = 0;
    int bad = 0;
    int i;
    for (i = 0; i < 10000; ++i) {
        uint8_t seed[COBFS4_SECRET_KEY_LEN];

        uint8_t out1[1024];
        uint8_t out2[1024];

        uint8_t out3[10];
        uint8_t out4[10];

        RAND_bytes((unsigned char *) &seed, sizeof(seed));

        seed_random(seed);

        if (deterministic_random(out1, sizeof(out1)) == -1) {
            ++bad;
            continue;
        }

        if (deterministic_random(out3, sizeof(out3)) == -1) {
            ++bad;
            continue;
        }

        seed_random(seed);

        if (deterministic_random(out2, sizeof(out2)) == -1) {
            ++bad;
            continue;
        }

        if (deterministic_random(out4, sizeof(out4)) == -1) {
            ++bad;
            continue;
        }

        if (memcmp(out1, out2, sizeof(out1)) != 0) {
            ++bad;
            continue;
        }

        if (memcmp(out3, out4, sizeof(out3)) != 0) {
            ++bad;
        } else {
            ++good;
        }
    }

    printf("Seeded random testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
