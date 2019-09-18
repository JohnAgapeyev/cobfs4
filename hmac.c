#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "hmac.h"

#define HMAC_LEN 32

int hmac_gen(const uint8_t *key, const size_t key_len, const uint8_t *message,
        const size_t mesg_len, uint8_t *hmac) {
    const EVP_MD *md = EVP_sha512_256();
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return -1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, key_len);
    if (!pkey) {
        goto free_md_ctx;
    }

    if (!EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey)) {
        goto error;
    }

    if (!EVP_DigestSignUpdate(mdctx, message, mesg_len)) {
        goto error;
    }

    uint8_t md_value[EVP_MAX_MD_SIZE];
    size_t md_len = 0;

    if (!EVP_DigestSignFinal(mdctx, md_value, &md_len)) {
        goto error;
    }

    if (md_len < HMAC_LEN) {
        goto error;
    }

    memcpy(hmac, md_value, HMAC_LEN);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    return 0;

error:
    EVP_PKEY_free(pkey);
free_md_ctx:
    EVP_MD_CTX_free(mdctx);
    OPENSSL_cleanse(hmac, HMAC_LEN);
    return -1;
}

int hmac_verify(const uint8_t* key, const size_t key_len, const uint8_t* message,
        const size_t mesg_len, const uint8_t* hmac) {
    uint8_t genned_hmac[HMAC_LEN];

    if (hmac_gen(key, key_len, message, mesg_len, genned_hmac)) {
        /* Failed to generate test HMAC */
        return -1;
    }

    if (CRYPTO_memcmp(hmac, genned_hmac, HMAC_LEN) == 0) {
        return 0;
    }
    return -1;
}
