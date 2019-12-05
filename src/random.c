#include <openssl/evp.h>
#include <string.h>

#include "constants.h"
#include "random.h"

#define RNG_OUTPUT_COUNT 768
#define USABLE_RNG_COUNT RNG_OUTPUT_COUNT - COBFS4_SECRET_KEY_LEN

struct rng_state {
    uint8_t chacha_key[COBFS4_SECRET_KEY_LEN];
    uint8_t seeded : 1;
};

//Static variables explicitly get zeroed out on initialization
static struct rng_state state;
static const uint8_t nonce[COBFS4_IV_LEN];

int encrypt_chacha(const uint8_t * restrict plaintext, size_t plain_len,
        const uint8_t key[static restrict COBFS4_SECRET_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_IV_LEN],
        uint8_t * restrict ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv)) {
        goto error;
    }

    int len;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_len)) {
        goto error;
    }

    int ciphertextlen = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        goto error;
    }

    ciphertextlen += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertextlen;

error:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

void seed_random(const uint8_t seed[static COBFS4_SECRET_KEY_LEN]) {
    memcpy(state.chacha_key, seed, COBFS4_SECRET_KEY_LEN);
    state.seeded = 1;
}

int deterministic_random(uint8_t *buf, size_t buf_len) {
    static uint8_t input_buffer[RNG_OUTPUT_COUNT];
    uint8_t output_buffer[RNG_OUTPUT_COUNT];

    if (!state.seeded) {
        goto error;
    }

    //Init the input buffer with 0, 1, 2, etc, but on a per-block basis
    for (uint32_t i = 0; i < RNG_OUTPUT_COUNT / COBFS4_BLOCK_LEN; ++i) {
        memset(input_buffer + (i * COBFS4_BLOCK_LEN), 0, COBFS4_BLOCK_LEN);
        memcpy(input_buffer + (i * COBFS4_BLOCK_LEN), &i, sizeof(i));
    }

    while(buf_len != 0) {
        if (encrypt_chacha(input_buffer, RNG_OUTPUT_COUNT, state.chacha_key, nonce, output_buffer) == -1) {
            goto error;
        }
        memcpy(state.chacha_key, output_buffer, COBFS4_SECRET_KEY_LEN);

        const size_t write_len = (buf_len < USABLE_RNG_COUNT) ? buf_len : USABLE_RNG_COUNT;
        memcpy(buf, output_buffer + COBFS4_SECRET_KEY_LEN, write_len);

        buf += write_len;
        buf_len -= write_len;
    }

    OPENSSL_cleanse(output_buffer, sizeof(output_buffer));

    return 0;

error:
    OPENSSL_cleanse(&state, sizeof(state));
    OPENSSL_cleanse(output_buffer, sizeof(output_buffer));
    return -1;
}
