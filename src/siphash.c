#include <openssl/evp.h>
#include <string.h>

#include "constants.h"
#include "siphash.h"

void siphash_init(struct siphash_ctx * restrict ctx, const uint8_t key[static restrict COBFS4_SIPHASH_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_SIPHASH_IV_LEN]) {
    memcpy(ctx->key, key, COBFS4_SIPHASH_KEY_LEN);
    memcpy(ctx->iv, iv, COBFS4_SIPHASH_IV_LEN);
}

enum cobfs4_return_code siphash(struct siphash_ctx * restrict ctx, uint16_t * restrict out_mask) {
    uint8_t md_value[EVP_MAX_MD_SIZE];
    size_t md_len = 0;
    EVP_PKEY *pkey = NULL;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        goto error;
    }

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_SIPHASH, NULL, ctx->key, COBFS4_SIPHASH_KEY_LEN);
    if (!pkey) {
        goto error;
    }

    if (!EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey)) {
        goto error;
    }

    if (!EVP_DigestSign(mdctx, md_value, &md_len, ctx->iv, COBFS4_SIPHASH_IV_LEN)) {
        goto error;
    }

    if (md_len < COBFS4_SIPHASH_IV_LEN) {
        goto error;
    }

    memcpy(ctx->iv, md_value, COBFS4_SIPHASH_IV_LEN);

    *out_mask = *((uint16_t *)md_value);

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
    OPENSSL_cleanse(out_mask, sizeof(uint16_t));
    return COBFS4_ERROR;
}
