#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "cobfs4.h"
#include "elligator.h"
#include "test.h"
#include "constants.h"

void test_elligator(void) {
    EVP_PKEY *init_pubkey_obj;
    EVP_PKEY *res_pubkey_obj;
    uint8_t init_pubkey[32];
    uint8_t res_pubkey[32];
    int count = 0;
    int good = 0;
    int bad = 0;
    int invalid = 0;
    uint8_t elligator[COBFS4_ELLIGATOR_LEN];
    enum cobfs4_return_code rc;
    size_t key_len = COBFS4_PUBKEY_LEN;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    EVP_PKEY_keygen_init(pctx);
    init_pubkey_obj = EVP_PKEY_new();

    for (count = 0; count < TEST_CASE_COUNT; ++count) {
        EVP_PKEY_keygen(pctx, &init_pubkey_obj);

        EVP_PKEY_get_raw_public_key(init_pubkey_obj, init_pubkey, &key_len);

        rc = elligator2_inv(init_pubkey_obj, elligator);
        if (rc == COBFS4_OK) {
            res_pubkey_obj = elligator2(elligator);
            if (res_pubkey_obj) {
                EVP_PKEY_get_raw_public_key(res_pubkey_obj, res_pubkey, &key_len);
                if (memcmp(init_pubkey, res_pubkey, 32) == 0) {
                    ++good;
                } else {
                    ++bad;
                }
                EVP_PKEY_free(res_pubkey_obj);
            }
        } else {
            ++invalid;
        }
    }
    EVP_PKEY_free(init_pubkey_obj);

    EVP_PKEY_CTX_free(pctx);

    printf("Elligator test ran %d times\nResults:\nGood: %d\nBad: %d\nInvalid: %d\n", count, good, bad, invalid);

    memset(elligator, 0, sizeof(elligator));
    res_pubkey_obj = elligator2(elligator);
    if (res_pubkey_obj) {
        EVP_PKEY_get_raw_public_key(res_pubkey_obj, res_pubkey, &key_len);

        int res = 0;
        for (int i = 0; i < 32; ++i) {
            if (elligator[i] != 0x00) {
                printf("All zero elligator input Bad!\n");
                res = 1;
                break;
            }
        }
        if (res == 0) {
            printf("All zero elligator input Good!\n");
        }
        EVP_PKEY_free(res_pubkey_obj);
    }

    good = 0;
    bad = 0;

    for (count = 0; count < TEST_CASE_COUNT; ++count) {
        RAND_bytes(elligator, sizeof(elligator));
        res_pubkey_obj = elligator2(elligator);
        if (res_pubkey_obj) {
            ++good;
            EVP_PKEY_free(res_pubkey_obj);
            continue;
        } else {
            ++bad;
            continue;
        }
    }
    printf("Elligator inverse only test ran %d times\nResults:\nGood: %d\nBad: %d\n", count, good, bad);
}
