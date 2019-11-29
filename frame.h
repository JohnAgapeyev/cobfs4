#ifndef COBFS4_FRAME_H
#define COBFS4_FRAME_H

int encrypt_aead(const uint8_t * restrict plaintext, size_t plain_len,
        const uint8_t * restrict aad, size_t aad_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        uint8_t * restrict ciphertext, uint8_t tag[static restrict COBFS4_TAG_LEN]);

int decrypt_aead(const uint8_t * restrict ciphertext, size_t cipher_len,
        const uint8_t * restrict aad, size_t aad_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        const uint8_t tag[static restrict COBFS4_TAG_LEN], uint8_t * restrict plaintext);

#endif
