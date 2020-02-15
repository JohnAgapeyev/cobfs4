#ifndef COBFS4_SIPHASH_H
#define COBFS4_SIPHASH_H

#include "constants.h"

struct siphash_ctx {
    uint8_t key[COBFS4_SIPHASH_KEY_LEN];
    uint8_t iv[COBFS4_SIPHASH_IV_LEN];
};

void siphash_init(struct siphash_ctx * restrict ctx, const uint8_t key[static restrict COBFS4_SIPHASH_KEY_LEN],
        const uint8_t iv[static restrict COBFS4_SIPHASH_IV_LEN]);

enum cobfs4_return_code siphash(struct siphash_ctx * restrict ctx, uint16_t * restrict out_mask);

#endif
