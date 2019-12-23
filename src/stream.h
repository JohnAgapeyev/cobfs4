#ifndef COBFS4_STREAM
#define COBFS4_STREAM

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "constants.h"
#include "siphash.h"
#include "random.h"

enum connection_type {
    COBFS4_CLIENT,
    COBFS4_SERVER,
};

struct cobfs4_stream {
    int fd;
    enum connection_type type;
    struct siphash_ctx siphash;
    struct rng_state rng;
    uint8_t read_buffer[COBFS4_MAX_DATA_LEN];
    uint8_t write_buffer[COBFS4_MAX_FRAME_LEN];
    bool initialized;
};

int cobfs4_server_init(struct cobfs4_stream *stream, int socket);
int cobfs4_client_init(struct cobfs4_stream *stream, int socket);
int cobfs4_read(struct cobfs4_stream * restrict stream, uint8_t buffer[static restrict COBFS4_MAX_DATA_LEN]);
int cobfs4_write(struct cobfs4_stream * restrict stream, uint8_t * restrict buffer, size_t buf_len);

#endif /* COBFS4_STREAM */
