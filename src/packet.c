#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "packet.h"
#include "elligator.h"
#include "hmac.h"
#include "ecdh.h"
#include "ntor.h"
#include "frame.h"

static inline void dump_hex(const uint8_t *data, size_t len) {
    (void)data;
    (void)len;
#if 0
    printf("Dumping:\n");
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
#endif
}

/*
 * Modified from:
 * https://stackoverflow.com/a/17554531
 */
static inline uint64_t rand_interval(const uint64_t min, const uint64_t max) {
    uint64_t r;
    const uint64_t range = 1 + max - min;
    const uint64_t buckets = UINT64_MAX / range;
    const uint64_t limit = buckets * range;

    /* Create equal size buckets all in a row, then fire randomly towards
     * the buckets until you land in one of them. All buckets are equally
     * likely. If you land off the end of the line of buckets, try again. */
    do {
        RAND_bytes((uint8_t *) &r, sizeof(r));
    } while (r >= limit);

    return min + (r / buckets);
}

/*
 * Returns a concatenation of the ntor public key and the identity key digest
 * This is used as an HMAC key throughout, so it's useful to have.
 */
static inline bool make_shared_data(const struct shared_data * restrict shared,
        uint8_t out_shared_data[static restrict COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN]) {
    size_t tmp_len = COBFS4_PUBKEY_LEN;
    if (!EVP_PKEY_get_raw_public_key(shared->ntor, out_shared_data, &tmp_len)) {
        OPENSSL_cleanse(out_shared_data, COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN);
        return false;
    }
    memcpy(out_shared_data + COBFS4_PUBKEY_LEN, shared->identity_digest, COBFS4_HASH_LEN);
    return true;
}

static bool validate_client_mac(const struct client_request * restrict req,
        const struct shared_data * restrict shared) {
    uint8_t mac_key[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    if (!make_shared_data(shared, mac_key)) {
        goto error;
    }

    if (hmac_verify(mac_key, sizeof(mac_key), req->elligator, COBFS4_ELLIGATOR_LEN, req->elligator_hmac)) {
        goto error;
    }

    //Get the number of hours since epoch
    const uint64_t hr_time = time(NULL) / 3600;
    int real_hour_len;

    uint8_t packet_hmac_data[COBFS4_ELLIGATOR_LEN + COBFS4_HMAC_LEN + COBFS4_EPOCH_HOUR_LEN + COBFS4_CLIENT_MAX_PAD_LEN + 1];
    memcpy(packet_hmac_data, req->elligator, COBFS4_ELLIGATOR_LEN);
    memcpy(packet_hmac_data + COBFS4_ELLIGATOR_LEN, req->random_padding, req->padding_len);
    memcpy(packet_hmac_data + COBFS4_ELLIGATOR_LEN + req->padding_len, req->elligator_hmac, COBFS4_HMAC_LEN);
    if ((real_hour_len = snprintf((char *) packet_hmac_data
                    + COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN, COBFS4_EPOCH_HOUR_LEN,
                    "%lu", hr_time)) < 0) {
        goto error;
    }

    size_t hmac_data_len = COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN + real_hour_len;

    //dump_hex(packet_hmac_data, hmac_data_len);

    //This is dumb but it works
    if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data, hmac_data_len, req->request_mac)) {
        if ((real_hour_len = snprintf((char *) packet_hmac_data
                        + COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN, COBFS4_EPOCH_HOUR_LEN,
                        "%lu", hr_time - 1)) < 0) {
            goto error;
        }
        hmac_data_len = COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN + real_hour_len;
        if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data, hmac_data_len, req->request_mac)) {
            if ((real_hour_len = snprintf((char *) packet_hmac_data
                            + COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN, COBFS4_EPOCH_HOUR_LEN,
                            "%lu", hr_time + 1)) < 0) {
                goto error;
            }
            hmac_data_len = COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN + real_hour_len;
            if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data, hmac_data_len, req->request_mac)) {
                goto error;
            }
        }
    }
    return true;
error:
    return false;
}

static bool validate_server_mac(const struct server_response * restrict resp,
        const struct shared_data * restrict shared) {

    uint8_t mac_key[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    uint8_t packet_hmac_data[COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN
        + COBFS4_HMAC_LEN + COBFS4_SERVER_MAX_PAD_LEN + COBFS4_EPOCH_HOUR_LEN];

    if (!make_shared_data(shared, mac_key)) {
        goto error;
    }

    if (hmac_verify(mac_key, sizeof(mac_key), resp->elligator, COBFS4_ELLIGATOR_LEN, resp->elligator_hmac)) {
        goto error;
    }

    memcpy(packet_hmac_data, resp->elligator, COBFS4_ELLIGATOR_LEN);
    memcpy(packet_hmac_data + COBFS4_ELLIGATOR_LEN, resp->auth_tag, COBFS4_AUTH_LEN);
    memcpy(packet_hmac_data + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN, resp->random_padding, resp->padding_len);
    memcpy(packet_hmac_data + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len, resp->elligator_hmac, COBFS4_HMAC_LEN);

    uint64_t hr_time = time(NULL) / 3600;
    int real_hour_len;

    if ((real_hour_len = snprintf((char *) packet_hmac_data
                    + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len + COBFS4_HMAC_LEN,
                    COBFS4_EPOCH_HOUR_LEN,
                    "%lu", hr_time)) < 0) {
        goto error;
    }

    size_t actual_data_len = COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len + COBFS4_HMAC_LEN + real_hour_len;

    //dump_hex(packet_hmac_data, actual_data_len);

    //This technically isn't necessary if I save the previous time string from the initial request, but oh well
    if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data,
            actual_data_len, resp->response_mac)) {
        if ((real_hour_len = snprintf((char *) packet_hmac_data
                        + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len + COBFS4_HMAC_LEN,
                        COBFS4_EPOCH_HOUR_LEN,
                        "%lu", hr_time + 1)) < 0) {
            goto error;
        }
        size_t actual_data_len = COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len + COBFS4_HMAC_LEN + real_hour_len;
        if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data,
                actual_data_len, resp->response_mac)) {
            if ((real_hour_len = snprintf((char *) packet_hmac_data
                            + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len + COBFS4_HMAC_LEN,
                            COBFS4_EPOCH_HOUR_LEN,
                            "%lu", hr_time - 1)) < 0) {
                goto error;
            }
            size_t actual_data_len = COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len + COBFS4_HMAC_LEN + real_hour_len;
            if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data,
                        actual_data_len, resp->response_mac)) {
                goto error;
            }
        }
    }

    return true;
error:
    return false;
}

int create_client_request(EVP_PKEY * restrict self_keypair,
        const struct shared_data * restrict shared,
        struct client_request * restrict out_req) {

    uint8_t mac_key[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    uint8_t request_mac_data[COBFS4_ELLIGATOR_LEN + COBFS4_HMAC_LEN
        + COBFS4_EPOCH_HOUR_LEN + COBFS4_CLIENT_MAX_PAD_LEN];

    if (elligator2(self_keypair, out_req->elligator)) {
        goto error;
    }

    out_req->padding_len = rand_interval(COBFS4_CLIENT_MIN_PAD_LEN, COBFS4_CLIENT_MAX_PAD_LEN);
    RAND_bytes(out_req->random_padding, out_req->padding_len);

    if (!make_shared_data(shared, mac_key)) {
        goto error;
    }

    if (hmac_gen(mac_key, sizeof(mac_key), out_req->elligator, COBFS4_ELLIGATOR_LEN, out_req->elligator_hmac)) {
        goto error;
    }

    //Get the number of hours since epoch
    const uint64_t hr_time = time(NULL) / 3600;

    int real_hour_len;
    if ((real_hour_len = snprintf((char *) out_req->epoch_hours, COBFS4_EPOCH_HOUR_LEN, "%lu", hr_time)) < 0) {
        goto error;
    }

    memcpy(request_mac_data, out_req->elligator, COBFS4_ELLIGATOR_LEN);
    memcpy(request_mac_data + COBFS4_ELLIGATOR_LEN, out_req->random_padding, out_req->padding_len);
    memcpy(request_mac_data + COBFS4_ELLIGATOR_LEN + out_req->padding_len, out_req->elligator_hmac, COBFS4_HMAC_LEN);
    memcpy(request_mac_data + COBFS4_ELLIGATOR_LEN + out_req->padding_len + COBFS4_HMAC_LEN, out_req->epoch_hours, real_hour_len);

    const size_t hmac_data_len = COBFS4_ELLIGATOR_LEN + out_req->padding_len + COBFS4_HMAC_LEN + real_hour_len;

    //dump_hex(request_mac_data, hmac_data_len);

    if (hmac_gen(mac_key, sizeof(mac_key), request_mac_data,
                hmac_data_len,
                out_req->request_mac)) {
        goto error;
    }

    return 0;

error:
    OPENSSL_cleanse(out_req, sizeof(*out_req));
    return -1;
}

int create_server_response(const struct shared_data * restrict shared,
        const struct client_request * restrict incoming_req,
        struct server_response * restrict out_resp,
        struct ntor_output * restrict out_ntor) {
    EVP_PKEY *client_pubkey = NULL;
    EVP_PKEY *ephem_key = NULL;
    uint8_t mac_key[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    uint8_t packet_mac_data[COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN
        + COBFS4_SERVER_MAX_PAD_LEN + COBFS4_HMAC_LEN + COBFS4_EPOCH_HOUR_LEN];

    if (!validate_client_mac(incoming_req, shared)) {
        return -1;
    }

    ephem_key = ecdh_key_alloc();
    if (!ephem_key) {
        return -1;
    }

    while(elligator2(ephem_key, out_resp->elligator) == -1) {
        EVP_PKEY_free(ephem_key);
        ephem_key = ecdh_key_alloc();
        if (ephem_key == NULL) {
            goto error;
        }
    }

    client_pubkey = elligator2_inv(incoming_req->elligator);
    if (!client_pubkey) {
        goto error;
    }

    if (server_ntor(ephem_key, client_pubkey, shared, out_ntor)) {
        goto error;
    }

    memcpy(out_resp->auth_tag, out_ntor->auth_tag, COBFS4_AUTH_LEN);
    out_resp->padding_len = rand_interval(COBFS4_SERVER_MIN_PAD_LEN, COBFS4_SERVER_MAX_PAD_LEN);
    RAND_bytes(out_resp->random_padding, out_resp->padding_len);

    if (!make_shared_data(shared, mac_key)) {
        goto error;
    }

    if (hmac_gen(mac_key, sizeof(mac_key), out_resp->elligator, COBFS4_ELLIGATOR_LEN, out_resp->elligator_hmac)) {
        goto error;
    }

    memcpy(packet_mac_data, out_resp->elligator, COBFS4_ELLIGATOR_LEN);
    memcpy(packet_mac_data + COBFS4_ELLIGATOR_LEN, out_ntor->auth_tag, COBFS4_AUTH_LEN);
    memcpy(packet_mac_data + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN, out_resp->random_padding, out_resp->padding_len);
    memcpy(packet_mac_data + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + out_resp->padding_len,
            out_resp->elligator_hmac, COBFS4_HMAC_LEN);
    memcpy(packet_mac_data + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + out_resp->padding_len + COBFS4_HMAC_LEN,
            incoming_req->epoch_hours, COBFS4_EPOCH_HOUR_LEN);

    const size_t packet_hmac_len = COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN
        + out_resp->padding_len + COBFS4_HMAC_LEN + COBFS4_EPOCH_HOUR_LEN;

    //dump_hex(packet_mac_data, packet_hmac_len);

    if (hmac_gen(mac_key, sizeof(mac_key), packet_mac_data, packet_hmac_len, out_resp->response_mac)) {
        goto error;
    }

    EVP_PKEY_free(ephem_key);
    EVP_PKEY_free(client_pubkey);
    return 0;

error:
    EVP_PKEY_free(ephem_key);
    EVP_PKEY_free(client_pubkey);
    OPENSSL_cleanse(out_resp, sizeof(*out_resp));
    OPENSSL_cleanse(out_ntor, sizeof(*out_ntor));
    return -1;
}

int client_process_server_response(EVP_PKEY * restrict self_keypair,
        const struct shared_data * restrict shared,
        struct server_response * restrict resp,
        struct ntor_output * restrict out_ntor) {
    if (!validate_server_mac(resp, shared)) {
        return -1;
    }

    EVP_PKEY *server_pubkey = elligator2_inv(resp->elligator);
    if (server_pubkey == NULL) {
        return -1;
    }

    if (client_ntor(self_keypair, server_pubkey, shared, out_ntor) == -1) {
        goto error;
    }

    if (CRYPTO_memcmp(out_ntor->auth_tag, resp->auth_tag, sizeof(COBFS4_AUTH_LEN)) != 0) {
        goto error;
    }

    EVP_PKEY_free(server_pubkey);
    return 0;

error:
    EVP_PKEY_free(server_pubkey);
    OPENSSL_cleanse(out_ntor, sizeof(*out_ntor));
    return -1;
}
