#include <openssl/evp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include "cobfs4.h"
#include "constants.h"
#include "frame.h"

static const uint8_t * restrict aad = (const uint8_t *) "cobfs4_library_aad";

enum cobfs4_return_code encrypt_aead(const uint8_t * restrict plaintext,
        size_t plain_len,
        const uint8_t * restrict aad, size_t aad_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        uint8_t * restrict out_ciphertext,
        uint8_t out_tag[static restrict COBFS4_TAG_LEN],
        size_t * restrict out_ciphertext_len) {
    if (plaintext == NULL) {
        goto error;
    }
    if (aad == NULL) {
        goto error;
    }
    if (out_ciphertext == NULL) {
        goto error;
    }
    if (out_ciphertext_len == NULL) {
        goto error;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto error;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv)) {
        goto error;
    }

    int len;
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        goto error;
    }

    if (!EVP_EncryptUpdate(ctx, out_ciphertext, &len, plaintext, plain_len)) {
        goto error;
    }

    int ciphertextlen = len;
    if (!EVP_EncryptFinal_ex(ctx, out_ciphertext + len, &len)) {
        goto error;
    }

    ciphertextlen += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, COBFS4_TAG_LEN, out_tag)) {
        goto error;
    }

    *out_ciphertext_len = ciphertextlen;
    EVP_CIPHER_CTX_free(ctx);
    return COBFS4_OK;

error:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return COBFS4_ERROR;
}

enum cobfs4_return_code decrypt_aead(const uint8_t * restrict ciphertext, size_t cipher_len,
        const uint8_t * restrict aad, size_t aad_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        const uint8_t tag[static restrict COBFS4_TAG_LEN], uint8_t * restrict out_plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto error;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv)) {
        goto error;
    }

    int len;
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        goto error;
    }

    if (!EVP_DecryptUpdate(ctx, out_plaintext, &len, ciphertext, cipher_len)) {
        goto error;
    }

    int plaintextlen = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, COBFS4_TAG_LEN, (uint8_t *) tag)) {
        goto error;
    }

    if (!EVP_DecryptFinal_ex(ctx, out_plaintext + len, &len)) {
        goto error;
    }
    plaintextlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return COBFS4_OK;

error:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return COBFS4_ERROR;
}

enum cobfs4_return_code make_frame(const uint8_t * restrict data, uint16_t data_len, uint16_t padding_len,
        enum frame_type type,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        uint8_t out_frame[static restrict data_len + padding_len + COBFS4_FRAME_PAYLOAD_OVERHEAD]) {
    uint8_t frame[COBFS4_MAX_FRAME_PAYLOAD_LEN];
    uint8_t plaintext[COBFS4_MAX_FRAME_PAYLOAD_LEN];
    size_t ciphertext_len = 0;
    uint16_t packet_data_len;
    enum cobfs4_return_code rc;

    if (data == NULL) {
        return COBFS4_ERROR;
    }

    if (data_len + padding_len > COBFS4_MAX_DATA_LEN) {
        return COBFS4_ERROR;
    }
    if (data_len + padding_len + COBFS4_FRAME_PAYLOAD_OVERHEAD > COBFS4_MAX_FRAME_PAYLOAD_LEN) {
        return COBFS4_ERROR;
    }

    memset(plaintext, 0, sizeof(plaintext));
    plaintext[0] = (uint8_t) type;
    packet_data_len = htons(data_len);
    memcpy(plaintext + 1, &packet_data_len, sizeof(packet_data_len));
    memcpy(plaintext + 3, data, data_len);

    rc = encrypt_aead(plaintext,
            data_len + padding_len + COBFS4_FRAME_PAYLOAD_OVERHEAD - COBFS4_TAG_LEN, aad,
            strlen((const char*) aad), key, iv, frame + COBFS4_TAG_LEN, frame, &ciphertext_len);
    if (rc != COBFS4_OK) {
        return COBFS4_ERROR;
    }
    memcpy(out_frame, frame, ciphertext_len + COBFS4_TAG_LEN);
    return COBFS4_OK;
}

enum cobfs4_return_code decrypt_frame(const uint8_t frame[static restrict COBFS4_MAX_FRAME_PAYLOAD_LEN],
        uint16_t frame_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        uint8_t out_data[static restrict COBFS4_MAX_DATA_LEN],
        uint16_t * restrict out_data_len,
        enum frame_type * restrict out_type) {
    uint8_t plaintext[COBFS4_MAX_FRAME_PAYLOAD_LEN];
    uint16_t payload_len = 0;

    if (out_data_len == NULL) {
        return COBFS4_ERROR;
    }
    if (out_type == NULL) {
        return COBFS4_ERROR;
    }
    if (frame_len > COBFS4_MAX_FRAME_PAYLOAD_LEN) {
        return COBFS4_ERROR;
    }
    if (frame_len < COBFS4_FRAME_PAYLOAD_OVERHEAD) {
        return COBFS4_ERROR;
    }

    if (decrypt_aead(frame + COBFS4_TAG_LEN, frame_len - COBFS4_TAG_LEN,
                aad, strlen((const char *) aad), key, iv, frame, plaintext) == -1) {
        return COBFS4_ERROR;
    }

    memcpy(&payload_len, plaintext + 1, sizeof(uint16_t));
    payload_len = ntohs(payload_len);
    if (payload_len > COBFS4_MAX_DATA_LEN) {
        return COBFS4_ERROR;
    }

    *out_type = (enum frame_type)plaintext[0];
    *out_data_len = payload_len;

    memcpy(out_data, plaintext + 3, payload_len);
    return COBFS4_OK;
}

