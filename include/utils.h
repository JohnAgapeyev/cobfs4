#ifndef COBFS4_UTILS
#define COBFS4_UTILS

#include <openssl/rand.h>

#include "random.h"

static inline void dump_hex(const uint8_t *data, size_t len) {
    printf("Dumping:\n");
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/*
 * Modified from:
 * https://stackoverflow.com/a/17554531
 */
static inline uint64_t rand_interval(const uint64_t min, const uint64_t max) {
    uint64_t r;
    const uint64_t range = 1 + max - min;
    const uint64_t buckets = UINT64_MAX / range;
    const uint64_t limit = buckets * range;

    /* Create equal size buckets all in a row, then fire randomly towards
     * the buckets until you land in one of them. All buckets are equally
     * likely. If you land off the end of the line of buckets, try again. */
    do {
        RAND_bytes((uint8_t *) &r, sizeof(r));
    } while (r >= limit);

    return min + (r / buckets);
}

static inline uint64_t deterministic_rand_interval(struct rng_state *state, const uint64_t min, const uint64_t max) {
    uint64_t r;
    const uint64_t range = 1 + max - min;
    const uint64_t buckets = UINT64_MAX / range;
    const uint64_t limit = buckets * range;

    /* Create equal size buckets all in a row, then fire randomly towards
     * the buckets until you land in one of them. All buckets are equally
     * likely. If you land off the end of the line of buckets, try again. */
    do {
        deterministic_random(state, (uint8_t *) &r, sizeof(r));
    } while (r >= limit);

    return min + (r / buckets);
}


#endif /* COBFS4_UTILS */
