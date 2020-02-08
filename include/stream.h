#ifndef COBFS4_STREAM
#define COBFS4_STREAM

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "constants.h"
#include "siphash.h"
#include "random.h"
#include "ntor.h"

enum connection_type {
    COBFS4_CLIENT,
    COBFS4_SERVER,
};

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

    bool initialized;
};

int cobfs4_server_init(struct cobfs4_stream * restrict stream, int socket,
        const uint8_t private_key[static restrict COBFS4_PRIVKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len,
        const uint8_t timing_seed[static restrict COBFS4_SERVER_TIMING_SEED_LEN]);

int cobfs4_client_init(struct cobfs4_stream * restrict stream, int socket,
        const uint8_t server_pubkey[static restrict COBFS4_PUBKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len);

int cobfs4_read(struct cobfs4_stream * restrict stream, uint8_t buffer[static restrict COBFS4_MAX_DATA_LEN]);
int cobfs4_write(struct cobfs4_stream * restrict stream, uint8_t * restrict buffer, size_t buf_len);

void cobfs4_cleanup(struct cobfs4_stream *stream);

#endif /* COBFS4_STREAM */
