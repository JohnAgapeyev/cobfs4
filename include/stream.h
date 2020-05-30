#ifndef COBFS4_STREAM
#define COBFS4_STREAM

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "constants.h"
#include "siphash.h"
#include "random.h"
#include "ntor.h"

struct cobfs4_stream {
    int fd;
    enum connection_type type;
    struct siphash_ctx read_siphash;
    struct siphash_ctx write_siphash;
    struct rng_state rng;
    struct shared_data shared;
    uint8_t timing_seed[COBFS4_SERVER_TIMING_SEED_LEN];

    uint8_t read_buffer[COBFS4_MAX_DATA_LEN];
    uint8_t write_buffer[COBFS4_MAX_FRAME_LEN];

    uint8_t read_key[COBFS4_SECRET_KEY_LEN];
    uint8_t read_nonce_prefix[COBFS4_NONCE_PREFIX_LEN];

    uint8_t write_key[COBFS4_SECRET_KEY_LEN];
    uint8_t write_nonce_prefix[COBFS4_NONCE_PREFIX_LEN];

    uint64_t read_frame_counter;
    uint64_t write_frame_counter;

    unsigned char initialized : 1;
    unsigned char nonblocking_read : 1;
};

#endif /* COBFS4_STREAM */
