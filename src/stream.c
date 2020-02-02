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

static int write_client_request(int fd, const struct client_request *req) {
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
        return -1;
    }

    ret = blocking_write(fd, buf, COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN + COBFS4_HMAC_LEN);
    if (ret < 0) {
        return -1;
    }
    return 0;
}

static int write_server_response(int fd, const struct server_response *resp) {
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
        return -1;
    }

    ret = blocking_write(fd, buf, server_response_len);
    if (ret < 0) {
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

    ret = blocking_read(fd, buf, COBFS4_SERVER_HANDSHAKE_LEN);
    if (ret <= 0) {
        goto error;
    }
    bytes_read += COBFS4_SERVER_HANDSHAKE_LEN;

    ret = hmac_gen(shared_buf, sizeof(shared_buf), buf, COBFS4_ELLIGATOR_LEN, marker);
    if (ret < 0) {
        goto error;
    }

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
    if ((bytes_read - marker_index + COBFS4_HMAC_LEN) < COBFS4_HMAC_LEN) {
        ret = blocking_read(fd, buf + bytes_read, COBFS4_HMAC_LEN - (bytes_read - marker_index));
        if (ret <= 0) {
            goto error;
        }
        bytes_read += ret;
    } else if ((bytes_read - (marker_index + COBFS4_HMAC_LEN)) > COBFS4_HMAC_LEN) {
        //We read more data than expected
        //TODO: Abstract this whole thing out for client/server and check if we're the server
        //the client should never send trailing garbage to the server, since it doesn't have the keys yet
        goto error;
    }

    memcpy(out_resp->elligator, buf, COBFS4_ELLIGATOR_LEN);
    memcpy(out_resp->auth_tag, buf + COBFS4_ELLIGATOR_LEN, COBFS4_AUTH_LEN);
    memcpy(out_resp->seed_frame, buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN, COBFS4_INLINE_SEED_FRAME_LEN);

    out_resp->padding_len = (marker_index - COBFS4_ELLIGATOR_LEN - COBFS4_AUTH_LEN - COBFS4_INLINE_SEED_FRAME_LEN);
    memcpy(out_resp->random_padding,
            buf + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + COBFS4_INLINE_SEED_FRAME_LEN,
            out_resp->padding_len);

    memcpy(out_resp->elligator_hmac, marker_location, COBFS4_HMAC_LEN);
    memcpy(out_resp->response_mac, marker_location + COBFS4_HMAC_LEN, COBFS4_HMAC_LEN);

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
    uint8_t timing_seed[COBFS4_SERVER_TIMING_SEED_LEN];
    struct stretched_key keys;
    EVP_PKEY *ephem = NULL;

    ephem = ecdh_key_alloc();
    if (ephem == NULL) {
        goto error;
    }

    if (create_client_request(ephem, &stream->shared, &request)) {
        goto error;
    }

    if (write_client_request(stream->fd, &request)) {
        goto error;
    }

    if (read_server_response(stream->fd, &stream->shared, &response)) {
        goto error;
    }

    if (client_process_server_response(ephem, &stream->shared, &response, timing_seed, &keys)) {
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
    return 0;

error:
    if (ephem) {
        EVP_PKEY_free(ephem);
    }
    OPENSSL_cleanse(timing_seed, sizeof(timing_seed));
    OPENSSL_cleanse(&keys, sizeof(keys));
    return -1;
}

static int read_client_request(int fd, const struct shared_data * restrict shared,
        struct client_request *out_req) {
    uint8_t buf[COBFS4_MAX_HANDSHAKE_SIZE];
    uint8_t shared_buf[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    uint8_t marker[COBFS4_HMAC_LEN];
    size_t bytes_read = 0;
    size_t old_bytes_read = 0;
    int ret;
    uint8_t *marker_location;
    size_t marker_index;

    memset(buf, 0, sizeof(buf));

    if (!make_shared_data(shared, shared_buf)) {
        goto error;
    }

    ret = blocking_read(fd, buf, COBFS4_CLIENT_HANDSHAKE_LEN);
    if (ret <= 0) {
        goto error;
    }
    bytes_read += COBFS4_CLIENT_HANDSHAKE_LEN;


    ret = hmac_gen(shared_buf, sizeof(shared_buf), buf, COBFS4_ELLIGATOR_LEN, marker);
    if (ret < 0) {
        goto error;
    }

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
    if ((bytes_read - marker_index - COBFS4_HMAC_LEN) < COBFS4_HMAC_LEN) {
        ret = blocking_read(fd, buf + bytes_read, COBFS4_HMAC_LEN - (bytes_read - marker_index));
        if (ret <= 0) {
            goto error;
        }
        bytes_read += ret;
    } else if ((bytes_read - marker_index - COBFS4_HMAC_LEN) > COBFS4_HMAC_LEN) {
        //We read more data than expected
        //TODO: Abstract this whole thing out for client/server and check if we're the server
        //the client should never send trailing garbage to the server, since it doesn't have the keys yet
        goto error;
    }

    memcpy(out_req->elligator, buf, COBFS4_ELLIGATOR_LEN);
    out_req->padding_len = marker_index - COBFS4_ELLIGATOR_LEN;
    memcpy(out_req->random_padding, buf + COBFS4_ELLIGATOR_LEN, out_req->padding_len);
    memcpy(out_req->elligator_hmac, marker_location, COBFS4_HMAC_LEN);
    memcpy(out_req->request_mac, marker_location + COBFS4_HMAC_LEN, COBFS4_HMAC_LEN);

    return 0;

error:
    OPENSSL_cleanse(buf, sizeof(buf));
    OPENSSL_cleanse(shared_buf, sizeof(shared_buf));
    OPENSSL_cleanse(marker, sizeof(marker));
    return -1;
}

static int perform_server_handshake(struct cobfs4_stream *stream) {
    struct client_request request;
    struct server_response response;
    struct stretched_key keys;
    EVP_PKEY *ephem = NULL;

    ephem = ecdh_key_alloc();
    if (ephem == NULL) {
        goto error;
    }

    if (read_client_request(stream->fd, &stream->shared, &request)) {
        goto error;
    }

    if (create_server_response(&stream->shared, &request, stream->timing_seed, &response, &keys)) {
        goto error;
    }

    if (write_server_response(stream->fd, &response)) {
        goto error;
    }

    memcpy(stream->read_key, keys.client2server_key, COBFS4_SECRET_KEY_LEN);
    memcpy(stream->read_nonce_prefix, keys.client2server_nonce_prefix, COBFS4_NONCE_PREFIX_LEN);
    memcpy(stream->write_key, keys.server2client_key, COBFS4_SECRET_KEY_LEN);
    memcpy(stream->write_nonce_prefix, keys.server2client_nonce_prefix, COBFS4_NONCE_PREFIX_LEN);

    siphash_init(&stream->read_siphash, keys.client2server_siphash_key, keys.client2server_siphash_iv);
    siphash_init(&stream->write_siphash, keys.server2client_siphash_key, keys.server2client_siphash_iv);

    seed_random(&stream->rng, stream->timing_seed);

    EVP_PKEY_free(ephem);
    OPENSSL_cleanse(&keys, sizeof(keys));
    return 0;

error:
    if (ephem) {
        EVP_PKEY_free(ephem);
    }
    OPENSSL_cleanse(&keys, sizeof(keys));
    return -1;
}

int cobfs4_client_init(struct cobfs4_stream * restrict stream, int socket,
        const uint8_t server_pubkey[static restrict COBFS4_PUBKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len) {
    EVP_PKEY *server_ntor = NULL;

    memset(stream, 0, sizeof(*stream));
    stream->fd = socket;
    stream->type = COBFS4_CLIENT;

    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        goto error;
    }

    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        goto error;
    }

    server_ntor = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_pubkey, COBFS4_PUBKEY_LEN);
    if (server_ntor == NULL) {
        goto error;
    }

    if (!elligator_valid(server_ntor)) {
        goto error;
    }

    stream->shared.ntor = server_ntor;

    if (hash_data(identity_data, identity_len, stream->shared.identity_digest)) {
        goto error;
    }

    if (perform_client_handshake(stream)) {
        goto error;
    }

    stream->initialized = true;
    return 0;

error:
    if (server_ntor) {
        EVP_PKEY_free(server_ntor);
    }
    return -1;
}

int cobfs4_server_init(struct cobfs4_stream * restrict stream, int socket,
        const uint8_t private_key[static restrict COBFS4_PRIVKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len,
        const uint8_t timing_seed[static restrict COBFS4_SERVER_TIMING_SEED_LEN]) {
    EVP_PKEY *server_ntor = NULL;

    memset(stream, 0, sizeof(*stream));
    stream->fd = socket;
    stream->type = COBFS4_SERVER;

    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        goto error;
    }

    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        goto error;
    }

    server_ntor = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, COBFS4_PRIVKEY_LEN);
    if (server_ntor == NULL) {
        goto error;
    }

    if (!elligator_valid(server_ntor)) {
        goto error;
    }

    stream->shared.ntor = server_ntor;

    if (hash_data(identity_data, identity_len, stream->shared.identity_digest)) {
        goto error;
    }

    memcpy(stream->timing_seed, timing_seed, COBFS4_SERVER_TIMING_SEED_LEN);

    if (perform_server_handshake(stream)) {
        goto error;
    }

    stream->initialized = true;
    return 0;

error:
    if (server_ntor) {
        EVP_PKEY_free(server_ntor);
    }
    return -1;
}

int cobfs4_read(struct cobfs4_stream * restrict stream, uint8_t buffer[static restrict COBFS4_MAX_DATA_LEN]) {
    int ret = 0;
    uint16_t len_mask = 0;
    uint16_t frame_len = 0;
    uint16_t plaintext_len = 0;
    enum frame_type type;
    uint8_t iv[COBFS4_IV_LEN];
    uint64_t tmp_frame_counter;

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

    if (siphash(&stream->read_siphash, &len_mask)) {
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

    if (decrypt_frame(stream->read_buffer + COBFS4_FRAME_LEN, frame_len, stream->read_key, iv, buffer, &plaintext_len, &type)) {
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

    return plaintext_len;

control_packet:
    OPENSSL_cleanse(buffer, COBFS4_MAX_DATA_LEN);
    return cobfs4_read(stream, buffer);

error:
    //This should close the socket after delay
    OPENSSL_cleanse(buffer, COBFS4_MAX_DATA_LEN);
    return -1;
}

int cobfs4_write(struct cobfs4_stream *restrict stream, uint8_t * restrict buffer, size_t buf_len) {
    uint16_t frame_len;
    uint16_t len_mask;
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
        desired_len = (uint16_t) deterministic_rand_interval(&stream->rng, COBFS4_FRAME_OVERHEAD, COBFS4_MAX_FRAME_LEN);
        content_len = desired_len - COBFS4_FRAME_OVERHEAD;

        data_len = (content_len <= buf_len) ? content_len : buf_len;
        padding_len = content_len - data_len;

        //Convert frame counter into big endian
        tmp_frame_counter = swap_uint64(stream->write_frame_counter);

        memcpy(iv, stream->write_nonce_prefix, COBFS4_NONCE_PREFIX_LEN);
        memcpy(iv + COBFS4_NONCE_PREFIX_LEN, &tmp_frame_counter, sizeof(tmp_frame_counter));

        if (make_frame(buffer, data_len, padding_len, TYPE_PAYLOAD,
                    stream->write_key, iv, stream->write_buffer + COBFS4_FRAME_LEN)) {
            goto error;
        }

        if (siphash(&stream->write_siphash, &len_mask)) {
            goto error;
        }

        frame_len = content_len + COBFS4_FRAME_PAYLOAD_OVERHEAD;
        frame_len ^= len_mask;

        memcpy(stream->write_buffer, &frame_len, COBFS4_FRAME_LEN);

        if (blocking_write(stream->fd, stream->write_buffer, content_len + COBFS4_FRAME_OVERHEAD) < 0) {
            goto error;
        }

        buffer += data_len;
        buf_len -= data_len;
    } while (buf_len > 0);

    return 0;

error:
    //This should close the socket after delay
    return -1;
}

