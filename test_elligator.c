#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "cobfs4.h"
#include "elligator.h"
#include "test.h"

void test_elligator(void) {
    EVP_PKEY *pkey;
    EVP_PKEY *peerkey;
    EVP_PKEY_CTX *pctx;
    size_t skeylen;
    uint8_t *skey;
    uint8_t *skey2;
    int skey3;
    int count;
    int good;
    int bad;
    int invalid;

    uint8_t elligator[32];

    /* size_t i; */

    count = 0;

    good = 0;
    bad = 0;
    invalid = 0;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    pkey = EVP_PKEY_new();

    EVP_PKEY_keygen_init(pctx);

    for (count = 0; count < 10000; ++count) {
        EVP_PKEY_keygen(pctx, &pkey);

        EVP_PKEY_get_raw_public_key(pkey, NULL, &skeylen);

        skey = OPENSSL_malloc(skeylen);
        skey2 = OPENSSL_malloc(skeylen);

        if (!EVP_PKEY_get_raw_public_key(pkey, skey, &skeylen)) {
            /*
            printf("Get raw call failed\n");
            printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
            */
        }

        skey3 = elligator2(pkey, elligator);

        if (skey3 == 0) {
            peerkey = elligator2_inv(elligator);
            if (peerkey) {
                if (!EVP_PKEY_get_raw_public_key(peerkey, skey2, &skeylen)) {
                    /*
                    printf("Get raw call failed\n");
                    printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
                    */
                }
                /*
                for (i = 0; i < 32; ++i) {
                    printf("%02x", skey[i]);
                }
                printf("\n");
                for (i = 0; i < 32; ++i) {
                    printf("%02x", skey2[i]);
                }
                printf("\n");
                */
                if (memcmp(skey, skey2, 32) == 0) {
                    /* printf("Elligator works as intended\n"); */
                    ++good;
                } else {
                    /* printf("Elligator FAILED\n"); */
                    ++bad;
                }
                EVP_PKEY_free(peerkey);
            }
        } else {
            /* printf("Generated key was not valid for elligator2\n"); */
            ++invalid;
        }

        OPENSSL_free(skey);
        OPENSSL_free(skey2);
    }
    EVP_PKEY_free(pkey);

    EVP_PKEY_CTX_free(pctx);

    printf("Elligator test ran %d times\nResults:\nGood: %d\nBad: %d\nInvalid: %d\n", count, good, bad, invalid);
}
