#include <openssl/rand.h>

#include <string.h>

#include "cobfs4.h"
#include "test.h"
#include "frame.h"
#include "constants.h"

void test_aead(void) {
    int good = 0;
    int bad = 0;
    int i;
    for (i = 0; i < 10000; ++i) {
        uint8_t key[COBFS4_SECRET_KEY_LEN];
        uint8_t iv[COBFS4_IV_LEN];
        uint8_t aad[32];
        uint8_t message[10000];
        uint8_t ciphertext[10016];
        uint8_t tag[COBFS4_TAG_LEN];
        uint8_t plaintext[10000];
        int cipher_len;

        RAND_bytes((unsigned char *) &key, sizeof(key));
        RAND_bytes((unsigned char *) &aad, sizeof(aad));
        RAND_bytes((unsigned char *) &message, sizeof(message));
        //Yes I know the IV should be a counter, these tests are for correctness, not security
        RAND_bytes((unsigned char *) &iv, sizeof(iv));

        if ((cipher_len = encrypt_aead(message, sizeof(message), aad, sizeof(aad), key, iv, ciphertext, tag)) <= 0) {
            ++bad;
            continue;
        }

        if (decrypt_aead(ciphertext, cipher_len, aad, sizeof(aad), key, iv, tag, plaintext) <= 0) {
            ++bad;
            continue;
        }

        if (memcmp(message, plaintext, sizeof(message)) == 0) {
            ++good;
        } else {
            ++bad;
        }
    }

    printf("Frame AEAD testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
