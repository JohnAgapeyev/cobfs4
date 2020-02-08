#include <openssl/evp.h>
#include <openssl/rand.h>

#include "cobfs4.h"
#include "hmac.h"
#include "constants.h"
#include "test.h"

void test_hmac(void) {
    uint8_t key[256];
    uint8_t key_len;

    uint8_t message[256];
    uint8_t mesg_len;

    uint8_t hmac[COBFS4_HMAC_LEN];

    int good = 0;
    int bad = 0;
    int i;

    for (i = 0; i < TEST_CASE_COUNT; ++i) {
        RAND_bytes(&key_len, 1);
        RAND_bytes(&mesg_len, 1);

        RAND_bytes(key, key_len);
        RAND_bytes(message, mesg_len);

        if (hmac_gen(key, key_len, message, mesg_len, hmac)) {
            ++bad;
            continue;
        }

        if (hmac_verify(key, key_len, message, mesg_len, hmac)) {
            ++bad;
        } else {
            ++good;
        }
    }
    printf("HMAC testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
