#ifndef COBFS4_FRAME_H
#define COBFS4_FRAME_H

#include <stdint.h>
#include "cobfs4.h"
#include "constants.h"

enum cobfs4_return_code encrypt_aead(const uint8_t * restrict plaintext, size_t plain_len,
        const uint8_t * restrict aad, size_t aad_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        uint8_t * restrict out_ciphertext, uint8_t out_tag[static restrict COBFS4_TAG_LEN], size_t * restrict out_ciphertext_len);

enum cobfs4_return_code decrypt_aead(const uint8_t * restrict ciphertext, size_t cipher_len,
        const uint8_t * restrict aad, size_t aad_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        const uint8_t tag[static restrict COBFS4_TAG_LEN], uint8_t * restrict out_plaintext);

enum cobfs4_return_code make_frame(const uint8_t * restrict data, uint16_t data_len, uint16_t padding_len,
        enum frame_type type,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        uint8_t out_frame[static restrict data_len + padding_len + COBFS4_FRAME_PAYLOAD_OVERHEAD]);

enum cobfs4_return_code decrypt_frame(const uint8_t frame[static restrict COBFS4_MAX_FRAME_PAYLOAD_LEN],
        uint16_t frame_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        uint8_t out_data[static restrict COBFS4_MAX_DATA_LEN],
        uint16_t * restrict out_data_len,
        enum frame_type * restrict out_type);

#endif
