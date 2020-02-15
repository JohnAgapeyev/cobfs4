#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

#include "ecdh.h"
#include "elligator.h"
#include "hash.h"

EVP_PKEY *ecdh_key_alloc(void) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int retry_count = 0;

retry:
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) {
        return NULL;
    }

    pkey = EVP_PKEY_new();
    if (!pkey) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    if (!elligator_valid(pkey)) {
        //Limit random retries to a 1 in 2**128 chance of failure
        if (++retry_count > 128) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return NULL;
        }
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        goto retry;
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

enum cobfs4_return_code ecdh_derive(EVP_PKEY * restrict self_keypair, EVP_PKEY * restrict remote_pub_key,
        uint8_t out_buffer[static restrict COBFS4_PUBKEY_LEN]) {
    EVP_PKEY_CTX *ctx;
    uint8_t skey[COBFS4_PUBKEY_LEN];
    size_t skeylen;

    ctx = EVP_PKEY_CTX_new(self_keypair, NULL);
    if (!ctx) {
        goto error;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto error;
    }

    if (EVP_PKEY_derive_set_peer(ctx, remote_pub_key) <= 0) {
        goto error;
    }

    skeylen = 32;
    if (EVP_PKEY_derive(ctx, skey, &skeylen) <= 0) {
        goto error;
    }

    if (hash_data(skey, skeylen, out_buffer) != COBFS4_OK) {
        goto error;
    }

    EVP_PKEY_CTX_free(ctx);
    return COBFS4_OK;

error:
    OPENSSL_cleanse(out_buffer, COBFS4_PUBKEY_LEN);
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    return COBFS4_ERROR;
}
