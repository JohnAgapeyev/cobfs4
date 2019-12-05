#ifndef COBFS4_RANDOM_H
#define COBFS4_RANDOM_H

#include "constants.h"

void seed_random(const uint8_t seed[static COBFS4_SECRET_KEY_LEN]);

int deterministic_random(uint8_t *buf, size_t buf_len);

#endif
