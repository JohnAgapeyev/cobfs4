#include <openssl/evp.h>
#include <openssl/rand.h>

#include "cobfs4.h"
#include "hmac.h"
#include "test.h"

void test_hmac(void) {
    unsigned char key[256];
    unsigned char key_len;

    unsigned char message[256];
    unsigned char mesg_len;

    unsigned char hmac[16];

    int good = 0;
    int bad = 0;
    int i;

    for (i = 0; i < 10000; ++i) {
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
