#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <openssl/evp.h>

#include "stream.h"
#include "constants.h"
#include "elligator.h"
#include "hash.h"
#include "packet.h"
#include "ecdh.h"

static int perform_client_handshake(struct cobfs4_stream *stream) {
    uint8_t message_buffer[COBFS4_MAX_HANDSHAKE_SIZE];
    struct client_request request;
    struct server_response response;

    EVP_PKEY *ephem = ecdh_key_alloc();

    if (create_client_request(ephem, &stream->shared, &request)) {
        EVP_PKEY_free(ephem);
        return -1;
    }

    return 0;
}

static int perform_server_handshake(struct cobfs4_stream *stream) {
    uint8_t message_buffer[COBFS4_MAX_HANDSHAKE_SIZE];
    struct client_request request;
    struct server_response response;
    return 0;
}

int cobfs4_client_init(struct cobfs4_stream *stream, int socket,
        const uint8_t server_pubkey[static restrict COBFS4_PUBKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len) {
    EVP_PKEY *server_ntor = NULL;

    memset(stream, 0, sizeof(*stream));
    stream->fd = socket;
    stream->type = COBFS4_CLIENT;

    server_ntor = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_pubkey, COBFS4_PUBKEY_LEN);
    if (server_ntor == NULL) {
        return -1;
    }

    if (!elligator_valid(server_ntor)) {
        EVP_PKEY_free(server_ntor);
        return -1;
    }

    stream->shared.ntor = server_ntor;

    if (hash_data(identity_data, identity_len, stream->shared.identity_digest)) {
        EVP_PKEY_free(server_ntor);
        return -1;
    }

    if (perform_client_handshake(stream)) {
        return -1;
    }

    stream->initialized = true;
    return 0;
}

int cobfs4_server_init(struct cobfs4_stream *stream, int socket,
        const uint8_t private_key[static restrict COBFS4_PRIVKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len) {
    EVP_PKEY *server_ntor = NULL;

    memset(stream, 0, sizeof(*stream));
    stream->fd = socket;
    stream->type = COBFS4_SERVER;

    server_ntor = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, COBFS4_PRIVKEY_LEN);
    if (server_ntor == NULL) {
        return -1;
    }

    if (!elligator_valid(server_ntor)) {
        EVP_PKEY_free(server_ntor);
        return -1;
    }

    stream->shared.ntor = server_ntor;

    if (hash_data(identity_data, identity_len, stream->shared.identity_digest)) {
        EVP_PKEY_free(server_ntor);
        return -1;
    }

    if (perform_server_handshake(stream)) {
        EVP_PKEY_free(server_ntor);
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

