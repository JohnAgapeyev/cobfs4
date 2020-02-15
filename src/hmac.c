#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "constants.h"
#include "hmac.h"

enum cobfs4_return_code hmac_gen(const uint8_t * restrict key, const size_t key_len,
        const uint8_t * restrict message, const size_t mesg_len,
        uint8_t hmac[static restrict COBFS4_HMAC_LEN]) {
    uint8_t md_value[EVP_MAX_MD_SIZE];
    size_t md_len = 0;
    const EVP_MD *md = EVP_sha512_256();
    EVP_PKEY *pkey = NULL;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        goto error;
    }

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, key_len);
    if (!pkey) {
        goto error;
    }

    if (!EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey)) {
        goto error;
    }

    if (!EVP_DigestSign(mdctx, md_value, &md_len, message, mesg_len)) {
        goto error;
    }

    if (md_len < COBFS4_HMAC_LEN) {
        goto error;
    }

    memcpy(hmac, md_value, COBFS4_HMAC_LEN);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    return COBFS4_OK;

error:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    OPENSSL_cleanse(hmac, COBFS4_HMAC_LEN);
    return COBFS4_ERROR;
}

enum cobfs4_return_code hmac_verify(const uint8_t * restrict key, const size_t key_len,
        const uint8_t * restrict message, const size_t mesg_len,
        const uint8_t hmac[static restrict COBFS4_HMAC_LEN]) {
    uint8_t genned_hmac[COBFS4_HMAC_LEN];

    if (hmac_gen(key, key_len, message, mesg_len, genned_hmac) != COBFS4_OK) {
        /* Failed to generate test HMAC */
        return COBFS4_ERROR;
    }

    if (CRYPTO_memcmp(hmac, genned_hmac, COBFS4_HMAC_LEN) == 0) {
        return COBFS4_OK;
    }
    return COBFS4_ERROR;
}
