#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/evp.h>

#include "stream.h"
#include "constants.h"
#include "elligator.h"
#include "hash.h"
#include "packet.h"
#include "ecdh.h"
#include "utils.h"
#include "hmac.h"
#include "frame.h"

static const struct timeval timeout = {
    .tv_sec = 1,
    .tv_usec = 0,
};

static int blocking_read(int sock, unsigned char * restrict buf, size_t buf_len) {
    ssize_t ret;

retry:
    ret = recv(sock, buf, buf_len, 0);
    if (ret == -1) {
        switch(errno) {
            case EINTR:
                goto retry;
            //We use blocking sockets so EAGAIN is timeout which means die
            case EAGAIN:
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
            case EINTR:
                goto retry;
            //We use blocking sockets so EAGAIN is timeout which means die
            case EAGAIN:
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
    return 0;
}

/*
 * Randomly sleeps between 0 and 10ms in increments of 100us
 */
static inline void random_wait(struct rng_state *rng) {
    const uint64_t choice = deterministic_rand_interval(rng, 0, 100);
    const struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = 1000 * 100 * choice,
    };
    struct timespec remainder = {0};
    const struct timespec *time = &delay;
    int ret;

retry:
    ret = nanosleep(time, &remainder);
    if (ret == -1 && errno == EINTR) {
        time = &remainder;
        goto retry;
    }
}

static enum cobfs4_return_code read_handshake_packet(const struct cobfs4_stream * restrict stream,
        uint8_t buf[static restrict COBFS4_MAX_HANDSHAKE_SIZE],
        uint8_t ** restrict out_marker_location) {
    uint8_t shared_buf[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    uint8_t marker[COBFS4_HMAC_LEN];
    size_t bytes_read = 0;
    size_t old_bytes_read = 0;
    int ret;
    size_t marker_index;
    const size_t min_packet_len = (stream->type == COBFS4_CLIENT) ? COBFS4_CLIENT_HANDSHAKE_LEN : COBFS4_SERVER_HANDSHAKE_LEN;
    enum cobfs4_return_code rc;

    if (stream == NULL) {
        goto error;
    }
    if (out_marker_location == NULL) {
        goto error;
    }

    if (make_shared_data(&stream->shared, shared_buf) != COBFS4_OK) {
        goto error;
    }

    ret = blocking_read(stream->fd, buf, min_packet_len);
    if (ret <= 0) {
        goto error;
    }
    bytes_read += min_packet_len;

    rc = hmac_gen(shared_buf, sizeof(shared_buf), buf, COBFS4_ELLIGATOR_LEN, marker);
    if (rc != COBFS4_OK) {
        goto error;
    }

retry:
    ret = nonblocking_read(stream->fd, buf + bytes_read, COBFS4_MAX_HANDSHAKE_SIZE - bytes_read);
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
    *out_marker_location = cobfs4_memmem(buf, bytes_read, marker, sizeof(marker));
    if (*out_marker_location == NULL) {
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

    marker_index = (*out_marker_location - buf);
    //We somehow didn't read the full trailing HMAC for the packet
    if ((bytes_read - marker_index + COBFS4_HMAC_LEN) < COBFS4_HMAC_LEN) {
        ret = blocking_read(stream->fd, buf + bytes_read, COBFS4_HMAC_LEN - (bytes_read - marker_index));
        if (ret <= 0) {
            goto error;
        }
        bytes_read += ret;
    } else if ((bytes_read - (marker_index + COBFS4_HMAC_LEN)) > COBFS4_HMAC_LEN) {
        //We read more data than expected
        if (stream->type == COBFS4_SERVER) {
            goto error;
        } else {
            //The server sent us the first packet
            //TODO: Do we need to handle this?
        }
        goto error;
    }

    OPENSSL_cleanse(shared_buf, sizeof(shared_buf));
    OPENSSL_cleanse(marker, sizeof(marker));
    return COBFS4_OK;

error:
    OPENSSL_cleanse(shared_buf, sizeof(shared_buf));
    OPENSSL_cleanse(marker, sizeof(marker));
    return COBFS4_ERROR;
}

static enum cobfs4_return_code write_client_request(int fd, const struct client_request *req) {
    unsigned char buf[COBFS4_MAX_HANDSHAKE_SIZE];
    int ret;
    size_t client_request_len = 0;

    memcpy(buf, req->elligator, COBFS4_ELLIGATOR_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN, req->random_padding, req->padding_len);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + req->padding_len, req->elligator_hmac, COBFS4_HMAC_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN, req->request_mac, COBFS4_HMAC_LEN);

    client_request_len = (COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN + COBFS4_HMAC_LEN);
    //Server expects a minimum of COBFS4_CLIENT_HANDSHAKE_LEN
    if (client_request_len - req->padding_len != COBFS4_CLIENT_HANDSHAKE_LEN) {
        return COBFS4_ERROR;
    }

    ret = blocking_write(fd, buf, COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN + COBFS4_HMAC_LEN);
    if (ret < 0) {
        return COBFS4_ERROR;
    }
    return COBFS4_OK;
}

static enum cobfs4_return_code write_server_response(int fd, const struct server_response *resp) {
    unsigned char buf[COBFS4_MAX_HANDSHAKE_SIZE];
    int ret;
    size_t server_response_len = 0;

    memcpy(buf, resp->elligator, COBFS4_ELLIGATOR_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN, resp->auth_tag, COBFS4_AUTH_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN, resp->seed_frame, COBFS4_INLINE_SEED_FRAME_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN,
            resp->random_padding, resp->padding_len);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN + resp->padding_len,
            resp->elligator_hmac, COBFS4_HMAC_LEN);
    memcpy(buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN + resp->padding_len + COBFS4_HMAC_LEN,
            resp->response_mac, COBFS4_HMAC_LEN);

    server_response_len = COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN
        + COBFS4_INLINE_SEED_FRAME_LEN + resp->padding_len + COBFS4_HMAC_LEN + COBFS4_HMAC_LEN;

    //Client expects COBFS4_SERVER_HANDSHAKE_LEN as a minimum
    if (server_response_len - resp->padding_len != COBFS4_SERVER_HANDSHAKE_LEN) {
        return COBFS4_ERROR;
    }

    ret = blocking_write(fd, buf, server_response_len);
    if (ret < 0) {
        return COBFS4_ERROR;
    }
    return COBFS4_OK;
}

static enum cobfs4_return_code read_server_response(const struct cobfs4_stream * restrict stream,
        struct server_response *out_resp) {
    uint8_t buf[COBFS4_MAX_HANDSHAKE_SIZE];
    uint8_t *marker_location;
    size_t marker_index;

    memset(buf, 0, sizeof(buf));

    if (read_handshake_packet(stream, buf, &marker_location) != COBFS4_OK) {
        goto error;
    }

    marker_index = (marker_location - buf);

    memcpy(out_resp->elligator, buf, COBFS4_ELLIGATOR_LEN);
    memcpy(out_resp->auth_tag, buf + COBFS4_ELLIGATOR_LEN, COBFS4_AUTH_LEN);
    memcpy(out_resp->seed_frame, buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN, COBFS4_INLINE_SEED_FRAME_LEN);

    out_resp->padding_len = (marker_index - COBFS4_ELLIGATOR_LEN - COBFS4_AUTH_LEN - COBFS4_INLINE_SEED_FRAME_LEN);
    memcpy(out_resp->random_padding,
            buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN,
            out_resp->padding_len);

    memcpy(out_resp->elligator_hmac, marker_location, COBFS4_HMAC_LEN);
    memcpy(out_resp->response_mac, marker_location + COBFS4_HMAC_LEN, COBFS4_HMAC_LEN);

    OPENSSL_cleanse(buf, sizeof(buf));
    return COBFS4_OK;

error:
    OPENSSL_cleanse(buf, sizeof(buf));
    return COBFS4_ERROR;
}

static enum cobfs4_return_code perform_client_handshake(struct cobfs4_stream *stream) {
    struct client_request request;
    struct server_response response;
    uint8_t timing_seed[COBFS4_SERVER_TIMING_SEED_LEN];
    struct stretched_key keys;
    EVP_PKEY *ephem = NULL;

    ephem = ecdh_key_alloc();
    if (ephem == NULL) {
        goto error;
    }

    if (create_client_request(ephem, &stream->shared, &request) != COBFS4_OK) {
        goto error;
    }

    if (write_client_request(stream->fd, &request) != COBFS4_OK) {
        goto error;
    }

    if (read_server_response(stream, &response) != COBFS4_OK) {
        goto error;
    }

    if (client_process_server_response(ephem, &stream->shared, &response, timing_seed, &keys) != COBFS4_OK) {
        goto error;
    }

    memcpy(stream->read_key, keys.server2client_key, COBFS4_SECRET_KEY_LEN);
    memcpy(stream->read_nonce_prefix, keys.server2client_nonce_prefix, COBFS4_NONCE_PREFIX_LEN);
    memcpy(stream->write_key, keys.client2server_key, COBFS4_SECRET_KEY_LEN);
    memcpy(stream->write_nonce_prefix, keys.client2server_nonce_prefix, COBFS4_NONCE_PREFIX_LEN);

    siphash_init(&stream->read_siphash, keys.server2client_siphash_key, keys.server2client_siphash_iv);
    siphash_init(&stream->write_siphash, keys.client2server_siphash_key, keys.client2server_siphash_iv);

    seed_random(&stream->rng, timing_seed);

    EVP_PKEY_free(ephem);
    OPENSSL_cleanse(timing_seed, sizeof(timing_seed));
    OPENSSL_cleanse(&keys, sizeof(keys));
    return COBFS4_OK;

error:
    if (ephem) {
        EVP_PKEY_free(ephem);
    }
    OPENSSL_cleanse(timing_seed, sizeof(timing_seed));
    OPENSSL_cleanse(&keys, sizeof(keys));
    return COBFS4_ERROR;
}

static enum cobfs4_return_code read_client_request(const struct cobfs4_stream * restrict stream,
        struct client_request *out_req) {
    uint8_t buf[COBFS4_MAX_HANDSHAKE_SIZE];
    uint8_t *marker_location;
    size_t marker_index;

    memset(buf, 0, sizeof(buf));

    if (read_handshake_packet(stream, buf, &marker_location) != COBFS4_OK) {
        goto error;
    }

    marker_index = (marker_location - buf);

    memcpy(out_req->elligator, buf, COBFS4_ELLIGATOR_LEN);
    out_req->padding_len = marker_index - COBFS4_ELLIGATOR_LEN;
    memcpy(out_req->random_padding, buf + COBFS4_ELLIGATOR_LEN, out_req->padding_len);
    memcpy(out_req->elligator_hmac, marker_location, COBFS4_HMAC_LEN);
    memcpy(out_req->request_mac, marker_location + COBFS4_HMAC_LEN, COBFS4_HMAC_LEN);

    OPENSSL_cleanse(buf, sizeof(buf));
    return COBFS4_OK;

error:
    OPENSSL_cleanse(buf, sizeof(buf));
    return COBFS4_ERROR;
}

static enum cobfs4_return_code perform_server_handshake(struct cobfs4_stream *stream) {
    struct client_request request;
    struct server_response response;
    struct stretched_key keys;

    if (read_client_request(stream, &request) != COBFS4_OK) {
        goto error;
    }

    if (create_server_response(&stream->shared, &request, stream->timing_seed, &response, &keys) != COBFS4_OK) {
        goto error;
    }

    if (write_server_response(stream->fd, &response) != COBFS4_OK) {
        goto error;
    }

    memcpy(stream->read_key, keys.client2server_key, COBFS4_SECRET_KEY_LEN);
    memcpy(stream->read_nonce_prefix, keys.client2server_nonce_prefix, COBFS4_NONCE_PREFIX_LEN);
    memcpy(stream->write_key, keys.server2client_key, COBFS4_SECRET_KEY_LEN);
    memcpy(stream->write_nonce_prefix, keys.server2client_nonce_prefix, COBFS4_NONCE_PREFIX_LEN);

    siphash_init(&stream->read_siphash, keys.client2server_siphash_key, keys.client2server_siphash_iv);
    siphash_init(&stream->write_siphash, keys.server2client_siphash_key, keys.server2client_siphash_iv);

    seed_random(&stream->rng, stream->timing_seed);

    OPENSSL_cleanse(&keys, sizeof(keys));
    return COBFS4_OK;

error:
    OPENSSL_cleanse(&keys, sizeof(keys));
    return COBFS4_ERROR;
}

enum cobfs4_return_code cobfs4_client_init(struct cobfs4_stream * restrict stream, int socket,
        const uint8_t server_pubkey[static restrict COBFS4_PUBKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len) {
    memset(stream, 0, sizeof(*stream));
    stream->fd = socket;
    stream->type = COBFS4_CLIENT;

    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        goto error;
    }

    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        goto error;
    }

    stream->shared.ntor = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_pubkey, COBFS4_PUBKEY_LEN);
    if (stream->shared.ntor == NULL) {
        goto error;
    }

    if (!elligator_valid(stream->shared.ntor)) {
        goto error;
    }

    if (hash_data(identity_data, identity_len, stream->shared.identity_digest) != COBFS4_OK) {
        goto error;
    }

    if (perform_client_handshake(stream) != COBFS4_OK) {
        goto error;
    }

    stream->initialized = true;
    return COBFS4_OK;

error:
    cobfs4_cleanup(stream);
    return COBFS4_ERROR;
}

enum cobfs4_return_code cobfs4_server_init(struct cobfs4_stream * restrict stream, int socket,
        const uint8_t private_key[static restrict COBFS4_PRIVKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len,
        const uint8_t timing_seed[static restrict COBFS4_SERVER_TIMING_SEED_LEN]) {
    memset(stream, 0, sizeof(*stream));
    stream->fd = socket;
    stream->type = COBFS4_SERVER;

    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        goto error;
    }

    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        goto error;
    }

    stream->shared.ntor = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, COBFS4_PRIVKEY_LEN);
    if (stream->shared.ntor == NULL) {
        goto error;
    }

    if (!elligator_valid(stream->shared.ntor)) {
        goto error;
    }

    if (hash_data(identity_data, identity_len, stream->shared.identity_digest) != COBFS4_OK) {
        goto error;
    }

    memcpy(stream->timing_seed, timing_seed, COBFS4_SERVER_TIMING_SEED_LEN);

    if (perform_server_handshake(stream) != COBFS4_OK) {
        goto error;
    }

    stream->initialized = true;
    return COBFS4_OK;

error:
    cobfs4_cleanup(stream);
    return COBFS4_ERROR;
}

void cobfs4_cleanup(struct cobfs4_stream *stream) {
    if (stream->shared.ntor) {
        EVP_PKEY_free(stream->shared.ntor);
    }

    random_wait(&stream->rng);
    shutdown(stream->fd, SHUT_RDWR);
    close(stream->fd);

    OPENSSL_cleanse(stream, sizeof(*stream));
}

enum cobfs4_return_code cobfs4_read(struct cobfs4_stream * restrict stream,
        uint8_t buffer[static restrict COBFS4_MAX_DATA_LEN],
        size_t * restrict out_len) {
    int ret = 0;
    uint16_t len_mask = 0;
    uint16_t frame_len = 0;
    uint16_t plaintext_len = 0;
    enum frame_type type;
    uint8_t iv[COBFS4_IV_LEN];
    uint64_t tmp_frame_counter;
    enum cobfs4_return_code rc;

    if (stream == NULL) {
        goto error;
    }
    if (out_len == NULL) {
        goto error;
    }

    if (!stream->initialized) {
        goto error;
    }

    ret = nonblocking_read(stream->fd, stream->read_buffer, sizeof(uint16_t));
    if (ret == -1) {
        goto error;
    } else if (ret == 0) {
        //EAGAIN, tell the caller to wait until read event
        return 0;
    } else if (ret == 1) {
        //We somehow read 1 byte from a 2 byte read, so block until we get the other byte
        if (blocking_read(stream->fd, stream->read_buffer + 1, 1) != 1) {
            goto error;
        }
    }

    if (stream->read_frame_counter == UINT64_MAX) {
        //Counter would wrap post increment
        goto error;
    }
    ++stream->read_frame_counter;

    if (siphash(&stream->read_siphash, &len_mask) != COBFS4_OK) {
        goto error;
    }

    memcpy(&frame_len, stream->read_buffer, sizeof(frame_len));

    frame_len ^= len_mask;

    //Frame length is too small
    if (frame_len < COBFS4_FRAME_PAYLOAD_OVERHEAD) {
        goto error;
    }

    //Frame length is too big
    if ((frame_len - COBFS4_FRAME_LEN) > COBFS4_MAX_FRAME_LEN) {
        goto error;
    }

    //The packets are <1500 bytes so we can safely block for them
    if (blocking_read(stream->fd, stream->read_buffer + COBFS4_FRAME_LEN, frame_len) != frame_len) {
        goto error;
    }

    //Convert frame counter into big endian
    tmp_frame_counter = swap_uint64(stream->read_frame_counter);

    memcpy(iv, stream->read_nonce_prefix, COBFS4_NONCE_PREFIX_LEN);
    memcpy(iv + COBFS4_NONCE_PREFIX_LEN, &tmp_frame_counter, sizeof(tmp_frame_counter));

    rc = decrypt_frame(stream->read_buffer + COBFS4_FRAME_LEN,
            frame_len,
            stream->read_key,
            iv,
            buffer,
            &plaintext_len,
            &type);
    if (rc != COBFS4_OK) {
        goto error;
    }

    switch(type) {
        case TYPE_PAYLOAD:
            break;
        case TYPE_PRNG_SEED:
            if (plaintext_len != COBFS4_SERVER_TIMING_SEED_LEN) {
                //We got a seed with an unexpected length
                goto error;
            }
            seed_random(&stream->rng, buffer);
            goto control_packet;
        default:
            //Unknown type
            goto control_packet;
    }

    *out_len = plaintext_len;
    return COBFS4_OK;

control_packet:
    OPENSSL_cleanse(buffer, COBFS4_MAX_DATA_LEN);
    return cobfs4_read(stream, buffer, out_len);

error:
    OPENSSL_cleanse(buffer, COBFS4_MAX_DATA_LEN);
    cobfs4_cleanup(stream);
    return COBFS4_ERROR;
}

enum cobfs4_return_code cobfs4_write(struct cobfs4_stream *restrict stream, uint8_t * restrict buffer, size_t buf_len) {
    uint16_t frame_len;
    uint16_t len_mask;
    uint64_t rand_output;
    uint16_t desired_len;
    uint16_t content_len;
    uint16_t data_len;
    uint16_t padding_len;
    uint64_t tmp_frame_counter;
    uint8_t iv[COBFS4_IV_LEN];

    if (!stream->initialized) {
        goto error;
    }

    do {
        if (stream->write_frame_counter == UINT64_MAX) {
            //Counter would wrap post increment
            goto error;
        }
        ++stream->write_frame_counter;

        //This cast should be safe due to the bounds on the random
        rand_output = deterministic_rand_interval(&stream->rng, COBFS4_FRAME_OVERHEAD, COBFS4_MAX_FRAME_LEN);
        if (rand_output < COBFS4_FRAME_OVERHEAD || rand_output > COBFS4_MAX_FRAME_LEN) {
            goto error;
        }
        desired_len = (uint16_t) rand_output;
        content_len = desired_len - COBFS4_FRAME_OVERHEAD;

        data_len = (content_len <= buf_len) ? content_len : buf_len;
        padding_len = content_len - data_len;

        //Convert frame counter into big endian
        tmp_frame_counter = swap_uint64(stream->write_frame_counter);

        memcpy(iv, stream->write_nonce_prefix, COBFS4_NONCE_PREFIX_LEN);
        memcpy(iv + COBFS4_NONCE_PREFIX_LEN, &tmp_frame_counter, sizeof(tmp_frame_counter));

        if (make_frame(buffer, data_len, padding_len, TYPE_PAYLOAD,
                    stream->write_key, iv, stream->write_buffer + COBFS4_FRAME_LEN) != COBFS4_OK) {
            goto error;
        }

        if (siphash(&stream->write_siphash, &len_mask) != COBFS4_OK) {
            goto error;
        }

        frame_len = content_len + COBFS4_FRAME_PAYLOAD_OVERHEAD;
        frame_len ^= len_mask;

        memcpy(stream->write_buffer, &frame_len, COBFS4_FRAME_LEN);

        random_wait(&stream->rng);

        if (blocking_write(stream->fd, stream->write_buffer, content_len + COBFS4_FRAME_OVERHEAD) < 0) {
            goto error;
        }

        buffer += data_len;
        buf_len -= data_len;
    } while (buf_len > 0);

    return COBFS4_OK;

error:
    cobfs4_cleanup(stream);
    return COBFS4_ERROR;
}
