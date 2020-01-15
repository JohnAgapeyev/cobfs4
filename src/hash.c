#include <openssl/evp.h>

#include <string.h>

#include "hash.h"
#include "constants.h"

int hash_data(uint8_t * restrict mesg, size_t mesg_len, uint8_t out_buf[static restrict COBFS4_HASH_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx) {
        goto error;
    }

    if (!EVP_DigestInit_ex(ctx, EVP_sha512_256(), NULL)) {
        goto error;
    }

    if (!EVP_DigestUpdate(ctx, mesg, mesg_len)) {
        goto error;
    }

    if (!EVP_DigestFinal_ex(ctx, out_buf, NULL)) {
        goto error;
    }

    EVP_MD_CTX_free(ctx);
    return 0;

error:
    OPENSSL_cleanse(out_buf, COBFS4_HASH_LEN);
    if (ctx) {
        EVP_MD_CTX_free(ctx);
    }
    return -1;
}
