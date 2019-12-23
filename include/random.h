#ifndef COBFS4_RANDOM_H
#define COBFS4_RANDOM_H

#include "constants.h"

struct rng_state {
    uint8_t chacha_key[COBFS4_SECRET_KEY_LEN];
    uint8_t seeded : 1;
};

void seed_random(struct rng_state * restrict state, const uint8_t seed[static restrict COBFS4_SECRET_KEY_LEN]);

int deterministic_random(struct rng_state * restrict state, uint8_t *buf, size_t buf_len);

#endif
