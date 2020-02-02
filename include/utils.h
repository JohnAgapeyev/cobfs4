#ifndef COBFS4_UTILS
#define COBFS4_UTILS

#include <openssl/rand.h>
#include <openssl/evp.h>

#include "random.h"

static inline void dump_hex(const uint8_t *data, size_t len) {
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

static inline uint64_t deterministic_rand_interval(struct rng_state *state,
        const uint64_t min, const uint64_t max) {
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

/*
 * Returns a concatenation of the ntor public key and the identity key digest
 * This is used as an HMAC key throughout, so it's useful to have.
 */
static inline bool make_shared_data(const struct shared_data * restrict shared,
        uint8_t out_shared_data[static restrict COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN]) {
    size_t tmp_len = COBFS4_PUBKEY_LEN;
    if (!EVP_PKEY_get_raw_public_key(shared->ntor, out_shared_data, &tmp_len)) {
        OPENSSL_cleanse(out_shared_data, COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN);
        return false;
    }
    memcpy(out_shared_data + COBFS4_PUBKEY_LEN, shared->identity_digest, COBFS4_HASH_LEN);
    return true;
}

static inline void *cobfs4_memmem(const void *haystack, size_t haystack_len,
        const void *needle, size_t needle_len) {
    if (haystack == NULL || haystack_len == 0) {
        return NULL;
    }
    if (needle == NULL || needle_len == 0) {
        return NULL;
    }
    const char *h = haystack;
    for (size_t i = 0; i < (haystack_len - needle_len); ++i, ++h) {
        if (memcmp(h, needle, needle_len) == 0) {
            return (void *) h;
        }
    }
    return NULL;
}

//Copied from https://stackoverflow.com/a/2637138
static inline uint64_t swap_uint64(uint64_t val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}


#endif /* COBFS4_UTILS */
