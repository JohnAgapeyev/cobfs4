#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "kdf.h"
#include "constants.h"

enum cobfs4_return_code hkdf(const uint8_t * restrict mesg,
        size_t mesg_len,
        const uint8_t * restrict salt,
        size_t salt_len,
        const uint8_t *restrict key,
        size_t key_len,
        uint8_t * restrict out_data,
        size_t out_len) {
    if (mesg == NULL) {
        goto error;
    }
    if (salt == NULL) {
        goto error;
    }
    if (key == NULL) {
        goto error;
    }
    if (out_data == NULL) {
        goto error;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        goto error;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto error;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        goto error;
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
        goto error;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0) {
        goto error;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, mesg, mesg_len) <= 0) {
        goto error;
    }
    if (EVP_PKEY_derive(pctx, out_data, &out_len) <= 0) {
        goto error;
    }
    EVP_PKEY_CTX_free(pctx);
    return COBFS4_OK;

error:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    OPENSSL_cleanse(out_data, out_len);
    return COBFS4_ERROR;
}
