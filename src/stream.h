#ifndef COBFS4_STREAM
#define COBFS4_STREAM

#include <stdint.h>
#include <sys/socket.h>

#include "constants.h"
#include "siphash.h"

struct cobfs4_stream {
    int fd;
    struct siphash_ctx siphash;
    uint8_t buffered_plaintext[1500];
    uint8_t buffered_request[1500];
};

int cobfs4_connect(struct cobfs4_stream *stream, const struct sockaddr *address, socklen_t address_len);
int cobfs4_bind(struct cobfs4_stream *stream, const struct sockaddr *address, socklen_t address_len);
int cobfs4_accept(struct cobfs4_stream *stream, const struct sockaddr *address, socklen_t address_len);
int cobfs4_read(struct cobfs4_stream *stream, uint8_t buffer[static restrict 1500]);
int cobfs4_write(struct cobfs4_stream *stream, uint8_t *buffer, size_t buff_len);

#endif /* COBFS4_STREAM */
