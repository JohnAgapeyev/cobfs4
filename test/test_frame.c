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
    for (i = 0; i < TEST_CASE_COUNT; ++i) {
        uint8_t key[COBFS4_SECRET_KEY_LEN];
        uint8_t iv[COBFS4_IV_LEN];
        uint8_t aad[32];
        uint8_t message[10000];
        uint8_t ciphertext[10016];
        uint8_t tag[COBFS4_TAG_LEN];
        uint8_t plaintext[10000];
        size_t cipher_len;

        RAND_bytes((unsigned char *) &key, sizeof(key));
        RAND_bytes((unsigned char *) &aad, sizeof(aad));
        RAND_bytes((unsigned char *) &message, sizeof(message));
        //Yes I know the IV should be a counter, these tests are for correctness, not security
        RAND_bytes((unsigned char *) &iv, sizeof(iv));

        if (encrypt_aead(message, sizeof(message), aad, sizeof(aad), key, iv, ciphertext, tag, &cipher_len) != COBFS4_OK) {
            ++bad;
            continue;
        }

        if (decrypt_aead(ciphertext, cipher_len, aad, sizeof(aad), key, iv, tag, plaintext) != COBFS4_OK) {
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

void test_frame(void) {
    int good = 0;
    int bad = 0;
    int i;

    for (i = 0; i < TEST_CASE_COUNT; ++i) {
        uint8_t key[COBFS4_SECRET_KEY_LEN];
        uint8_t iv[COBFS4_IV_LEN];
        uint8_t message[COBFS4_MAX_DATA_LEN - 10];
        uint8_t ciphertext[COBFS4_MAX_FRAME_PAYLOAD_LEN];
        uint8_t plaintext[COBFS4_MAX_DATA_LEN - 10];
        uint16_t frame_len = 0;
        enum frame_type type = TYPE_PAYLOAD;
        enum frame_type recv_type;

        RAND_bytes((unsigned char *) &key, sizeof(key));
        RAND_bytes((unsigned char *) &message, sizeof(message));
        //Yes I know the IV should be a counter, these tests are for correctness, not security
        RAND_bytes((unsigned char *) &iv, sizeof(iv));

        type = TYPE_PAYLOAD;

        if (make_frame(message, sizeof(message), 10, type, key, iv, ciphertext) != COBFS4_OK) {
            ++bad;
            continue;
        }

        if (decrypt_frame(ciphertext, sizeof(message) + 10 + COBFS4_FRAME_PAYLOAD_OVERHEAD,
                    key, iv, plaintext, &frame_len, &recv_type) != COBFS4_OK) {
            ++bad;
            continue;
        }

        if (memcmp(message, plaintext, frame_len) == 0 && type == recv_type) {
            ++good;
        } else {
            ++bad;
        }
    }

    printf("Normal frame packet testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);

    good = 0;
    bad = 0;
    for (i = 0; i < TEST_CASE_COUNT; ++i) {
        uint8_t key[COBFS4_SECRET_KEY_LEN];
        uint8_t iv[COBFS4_IV_LEN];
        uint8_t message[COBFS4_MAX_DATA_LEN - 10];
        uint8_t ciphertext[COBFS4_MAX_FRAME_PAYLOAD_LEN];
        uint8_t plaintext[COBFS4_MAX_DATA_LEN - 10];
        uint16_t frame_len = 0;
        enum frame_type type = TYPE_PAYLOAD;
        enum frame_type recv_type;

        RAND_bytes((unsigned char *) &key, sizeof(key));
        RAND_bytes((unsigned char *) &message, sizeof(message));
        //Yes I know the IV should be a counter, these tests are for correctness, not security
        RAND_bytes((unsigned char *) &iv, sizeof(iv));

        type = TYPE_PAYLOAD;

        if (make_frame(message, 0, 1100, type, key, iv, ciphertext) != COBFS4_OK) {
            ++bad;
            continue;
        }

        if (decrypt_frame(ciphertext, 1100 + COBFS4_FRAME_PAYLOAD_OVERHEAD,
                    key, iv, plaintext, &frame_len, &recv_type) != COBFS4_OK) {
            ++bad;
            continue;
        }

        if (memcmp(message, plaintext, frame_len) == 0 && type == recv_type) {
            ++good;
        } else {
            ++bad;
        }
    }

    printf("All padding frame packet testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);

    good = 0;
    bad = 0;
    for (i = 0; i < TEST_CASE_COUNT; ++i) {
        uint8_t key[COBFS4_SECRET_KEY_LEN];
        uint8_t iv[COBFS4_IV_LEN];
        uint8_t message[COBFS4_MAX_DATA_LEN];
        uint8_t ciphertext[COBFS4_MAX_FRAME_PAYLOAD_LEN];
        uint8_t plaintext[COBFS4_MAX_DATA_LEN];
        uint16_t frame_len = 0;
        enum frame_type type = TYPE_PAYLOAD;
        enum frame_type recv_type;

        RAND_bytes((unsigned char *) &key, sizeof(key));
        RAND_bytes((unsigned char *) &message, sizeof(message));
        //Yes I know the IV should be a counter, these tests are for correctness, not security
        RAND_bytes((unsigned char *) &iv, sizeof(iv));

        type = TYPE_PAYLOAD;

        if (make_frame(message, sizeof(message), 0, type, key, iv, ciphertext) != COBFS4_OK) {
            ++bad;
            continue;
        }

        if (decrypt_frame(ciphertext, sizeof(message) + COBFS4_FRAME_PAYLOAD_OVERHEAD,
                    key, iv, plaintext, &frame_len, &recv_type) != COBFS4_OK) {
            ++bad;
            continue;
        }

        if (memcmp(message, plaintext, frame_len) == 0 && type == recv_type) {
            ++good;
        } else {
            ++bad;
        }
    }

    printf("No padding frame packet testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);

    good = 0;
    bad = 0;
    for (i = 0; i < TEST_CASE_COUNT; ++i) {
        uint8_t key[COBFS4_SECRET_KEY_LEN];
        uint8_t iv[COBFS4_IV_LEN];
        uint8_t message[20];
        uint8_t ciphertext[COBFS4_MAX_FRAME_PAYLOAD_LEN];
        uint8_t plaintext[20];
        uint16_t frame_len = 0;
        enum frame_type type = TYPE_PAYLOAD;
        enum frame_type recv_type;

        RAND_bytes((unsigned char *) &key, sizeof(key));
        RAND_bytes((unsigned char *) &message, sizeof(message));
        //Yes I know the IV should be a counter, these tests are for correctness, not security
        RAND_bytes((unsigned char *) &iv, sizeof(iv));

        type = TYPE_PAYLOAD;

        if (make_frame(message, sizeof(message), 0, type, key, iv, ciphertext) != COBFS4_OK) {
            ++bad;
            continue;
        }

        if (decrypt_frame(ciphertext, sizeof(message) + COBFS4_FRAME_PAYLOAD_OVERHEAD,
                    key, iv, plaintext, &frame_len, &recv_type) != COBFS4_OK) {
            ++bad;
            continue;
        }

        if (memcmp(message, plaintext, frame_len) == 0 && type == recv_type) {
            ++good;
        } else {
            ++bad;
        }
    }

    printf("Small frame packet testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
