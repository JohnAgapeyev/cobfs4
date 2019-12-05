#include <openssl/evp.h>

#include "constants.h"
#include "frame.h"

int encrypt_aead(const uint8_t * restrict plaintext, size_t plain_len,
        const uint8_t * restrict aad, size_t aad_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        uint8_t * restrict ciphertext, uint8_t * restrict tag) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)) {
        goto error;
    }

    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        goto error;
    }

    int len;
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        goto error;
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_len)) {
        goto error;
    }

    int ciphertextlen = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        goto error;
    }

    ciphertextlen += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, COBFS4_TAG_LEN, tag)) {
        goto error;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertextlen;

error:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int decrypt_aead(const uint8_t * restrict ciphertext, size_t cipher_len,
        const uint8_t * restrict aad, size_t aad_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        const uint8_t tag[static restrict COBFS4_TAG_LEN], uint8_t * restrict plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)) {
        goto error;
    }

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        goto error;
    }

    int len;
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        goto error;
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len)) {
        goto error;
    }

    int plaintextlen = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, COBFS4_TAG_LEN, (uint8_t *) tag)) {
        goto error;
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        goto error;
    }

    plaintextlen += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintextlen;

error:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
