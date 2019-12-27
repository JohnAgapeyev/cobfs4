#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <openssl/evp.h>

#include "constants.h"
#include "stream.h"

static int perform_client_handshake(struct cobfs4_stream *stream) {
    return 0;
}

static int perform_server_handshake(struct cobfs4_stream *stream) {
    return 0;
}

int cobfs4_client_init(struct cobfs4_stream *stream, int socket) {
    memset(stream, 0, sizeof(*stream));
    stream->fd = socket;
    stream->type = COBFS4_CLIENT;

    if (perform_client_handshake(stream)) {
        return -1;
    }

    stream->initialized = true;
    return 0;
}

int cobfs4_server_init(struct cobfs4_stream *stream, int socket,
        const uint8_t private_key[static restrict COBFS4_PUBKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len) {
    memset(stream, 0, sizeof(*stream));
    stream->fd = socket;
    stream->type = COBFS4_SERVER;



    if (hash_data(identity_data, identity_len, stream->shared.identity_digest)) {
        return -1;
    }

    if (perform_server_handshake(stream)) {
        return -1;
    }

    stream->initialized = true;
    return 0;
}

int cobfs4_read(struct cobfs4_stream * restrict stream, uint8_t buffer[static restrict COBFS4_MAX_DATA_LEN]) {
    if (!stream->initialized) {
        return -1;
    }
    return 0;
}

int cobfs4_write(struct cobfs4_stream *restrict stream, uint8_t * restrict buffer, size_t buf_len) {
    if (!stream->initialized) {
        return -1;
    }
    return 0;
}

