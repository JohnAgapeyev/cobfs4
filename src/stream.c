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
#include "utils.h"
#include "hmac.h"

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

static int read_server_response(int fd, const struct shared_data * restrict shared,
        struct server_response *out_resp) {
    uint8_t buf[COBFS4_MAX_HANDSHAKE_SIZE];
    uint8_t shared_buf[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    uint8_t marker[COBFS4_HMAC_LEN];
    size_t bytes_read = 0;
    size_t old_bytes_read = 0;
    int ret;
    uint8_t *marker_location;
    size_t marker_index;

    if (!make_shared_data(shared, shared_buf)) {
        goto error;
    }

    ret = hmac_gen(shared_buf, sizeof(shared_buf), buf, COBFS4_ELLIGATOR_LEN, marker);
    if (ret <= 0) {
        goto error;
    }

    ret = blocking_read(fd, buf, COBFS4_SERVER_HANDSHAKE_LEN);
    if (ret <= 0) {
        goto error;
    }
    bytes_read += COBFS4_SERVER_HANDSHAKE_LEN;

retry:
    ret = nonblocking_read(fd, buf + bytes_read, COBFS4_MAX_HANDSHAKE_SIZE - bytes_read);
    if (ret < 0) {
        goto error;
    } else if (ret == 0) {
        //We hit EAGAIN
        //Try to find the MAC with what we have
        goto done;
    } else {
        //We got some data
        bytes_read += ret;
        if (bytes_read >= COBFS4_MAX_HANDSHAKE_SIZE) {
            bytes_read = COBFS4_MAX_HANDSHAKE_SIZE;
            goto done;
        }
        goto retry;
    }

done:
    marker_location = cobfs4_memmem(buf, bytes_read, marker, sizeof(marker));
    if (marker_location == NULL) {
        if (bytes_read == COBFS4_MAX_HANDSHAKE_SIZE) {
            //This is not a valid handshake
            goto error;
        }
        if (bytes_read == old_bytes_read) {
            //We hit EAGAIN on our last retry without reading anything new
            goto error;
        }
        old_bytes_read = bytes_read;
        goto retry;
    }

    marker_index = (marker_location - buf);
    //We somehow didn't read the full trailing HMAC for the packet
    if ((bytes_read - marker_index) < COBFS4_HMAC_LEN) {
        ret = blocking_read(fd, buf + bytes_read, COBFS4_HMAC_LEN - (bytes_read - marker_index));
        if (ret <= 0) {
            goto error;
        }
        bytes_read += ret;
    } else if ((bytes_read - marker_index) > COBFS4_HMAC_LEN) {
        //We read more data than expected
        //TODO: Abstract this whole thing out for client/server and check if we're the server
        //the client should never send trailing garbage to the server, since it doesn't have the keys yet
        goto error;
    }

    memcpy(out_resp->elligator, buf, COBFS4_ELLIGATOR_LEN);
    memcpy(out_resp->auth_tag, buf + COBFS4_ELLIGATOR_LEN, COBFS4_AUTH_LEN);
    memcpy(out_resp->seed_frame, buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN, COBFS4_INLINE_SEED_FRAME_LEN);

    out_resp->padding_len = (marker - buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN);
    memcpy(out_resp->random_padding,
            buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN,
            out_resp->padding_len);

    memcpy(out_resp->elligator_hmac, marker, COBFS4_HMAC_LEN);
    memcpy(out_resp->response_mac, marker + COBFS4_HMAC_LEN, COBFS4_HMAC_LEN);

    return 0;

error:
    OPENSSL_cleanse(buf, sizeof(buf));
    OPENSSL_cleanse(shared_buf, sizeof(shared_buf));
    OPENSSL_cleanse(marker, sizeof(marker));
    return -1;
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

    if (read_server_response(stream->fd, &stream->shared, &response) <= 0) {
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

