#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

#include "ecdh.h"
#include "hash.h"

EVP_PKEY *ecdh_key_alloc(void) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

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

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

int ecdh_derive(EVP_PKEY *self_keypair, EVP_PKEY *remote_pub_key, uint8_t out_buffer[static 32]) {
    EVP_PKEY_CTX *ctx;
    uint8_t skey[32];
    size_t skeylen;

    ctx = EVP_PKEY_CTX_new(self_keypair, NULL);
    if (!ctx) {
        return -1;
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

    if (hash_data(skey, skeylen, skey)) {
        goto error;
    }

    memcpy(out_buffer, skey, 32);

    EVP_PKEY_CTX_free(ctx);

    return 0;

error:
    EVP_PKEY_CTX_free(ctx);
    return -1;
}
