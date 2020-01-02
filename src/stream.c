#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <openssl/evp.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include "stream.h"
#include "constants.h"
#include "elligator.h"
#include "hash.h"
#include "packet.h"
#include "ecdh.h"

static int blocking_read(int sock, unsigned char * restrict buf, size_t buf_len) {
    ssize_t ret;

retry:
    ret = recv(sock, buf, buf_len, 0);
    if (ret == -1) {
        switch(errno) {
            case EAGAIN:
            case EINTR:
                goto retry;
            case EBADF:
            case ECONNREFUSED:
            case EFAULT:
            case EINVAL:
            case ENOMEM:
            case ENOTCONN:
            case ENOTSOCK:
                return -1;
        }
    } else if (ret == 0) {
        return -1;
    }

    if ((size_t) ret < buf_len) {
        buf_len -= ret;
        buf += ret;
        goto retry;
    }

    return ret;
}

static int nonblocking_read(int sock, unsigned char * restrict buf, size_t buf_len) {
    ssize_t ret;

retry:
    ret = recv(sock, buf, buf_len, MSG_DONTWAIT);
    if (ret == -1) {
        switch(errno) {
            case EAGAIN:
                return 0;
            case EINTR:
                goto retry;
            case EBADF:
            case ECONNREFUSED:
            case EFAULT:
            case EINVAL:
            case ENOMEM:
            case ENOTCONN:
            case ENOTSOCK:
                return -1;
        }
    } else if (ret == 0) {
        return -1;
    }

    if ((size_t) ret < buf_len) {
        buf_len -= ret;
        buf += ret;
        goto retry;
    }

    return ret;
}

static int blocking_write(int sock, unsigned char * restrict buf, size_t buf_len) {
    ssize_t ret;

retry:
    ret = send(sock, buf, buf_len, MSG_NOSIGNAL);
    if (ret == -1) {
        switch(errno) {
            case EAGAIN:
            case EINTR:
                goto retry;
            case EACCES:
            case EALREADY:
            case EBADF:
            case ECONNRESET:
            case EDESTADDRREQ:
            case EFAULT:
            case EINVAL:
            case EISCONN:
            case EMSGSIZE:
            case ENOBUFS:
            case ENOMEM:
            case ENOTCONN:
            case ENOTSOCK:
            case EOPNOTSUPP:
            case EPIPE:
                return -1;
        }
    } else if (ret == 0) {
        return -1;
    }

    if ((size_t) ret < buf_len) {
        buf_len -= ret;
        buf += ret;
        goto retry;
    }

    return ret;
}

static int write_client_request(int fd, const struct client_request *req) {
    unsigned char buf[COBFS4_MAX_HANDSHAKE_SIZE];
    int ret;

    memcpy(buf, req->elligator, COBFS4_ELLIGATOR_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN, req->random_padding, req->padding_len);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + req->padding_len, req->elligator_hmac, COBFS4_HMAC_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN, req->request_mac, COBFS4_HMAC_LEN);

    ret = blocking_write(fd, buf, COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN + COBFS4_HMAC_LEN);
    if (ret <= 0) {
        return -1;
    }
    return 0;
}

static int write_server_response(int fd, const struct server_response *resp) {
    unsigned char buf[COBFS4_MAX_HANDSHAKE_SIZE];
    int ret;

    memcpy(buf, resp->elligator, COBFS4_ELLIGATOR_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN, resp->auth_tag, COBFS4_AUTH_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN, resp->seed_frame, COBFS4_INLINE_SEED_FRAME_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN,
            resp->random_padding, resp->padding_len);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN + resp->padding_len,
            resp->elligator_hmac, COBFS4_HMAC_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN + resp->padding_len + COBFS4_HMAC_LEN,
            resp->response_mac, COBFS4_HMAC_LEN);

    ret = blocking_write(fd, buf,
            COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN + resp->padding_len + COBFS4_HMAC_LEN);
    if (ret <= 0) {
        return -1;
    }
    return 0;
}

static int read_server_response(int fd, struct server_response *out_resp) {
    unsigned char buf[COBFS4_MAX_HANDSHAKE_SIZE];
    int ret;

}

static int perform_client_handshake(struct cobfs4_stream *stream) {
    struct client_request request;
    struct server_response response;

    EVP_PKEY *ephem = ecdh_key_alloc();

    if (create_client_request(ephem, &stream->shared, &request)) {
        EVP_PKEY_free(ephem);
        return -1;
    }

    if (write_client_request(stream->fd, &request) <= 0) {
        EVP_PKEY_free(ephem);
        return -1;
    }

    if (read_server_response(stream->fd, &response) <= 0) {
        EVP_PKEY_free(ephem);
        return -1;
    }

    EVP_PKEY_free(ephem);

    return 0;
}

static int perform_server_handshake(struct cobfs4_stream *stream) {
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

