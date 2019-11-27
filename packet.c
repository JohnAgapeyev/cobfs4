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

static bool validate_client_mac(const struct client_request *req,
        EVP_PKEY *ntor_keypair,
        const uint8_t identity_digest[static 32]) {
    uint8_t mac_key[32 + 32];
    size_t tmp_len = 32;

    if (!EVP_PKEY_get_raw_public_key(ntor_keypair, mac_key, &tmp_len)) {
        goto error;
    }
    memcpy(mac_key + 32, identity_digest, 32);

    if (hmac_verify(mac_key, sizeof(mac_key), req->elligator, REPRESENTATIVE_LEN, req->elligator_hmac)) {
        goto error;
    }

    //Get the number of hours since epoch
    const uint64_t hr_time = time(NULL) / 3600;
    int real_hour_len;

    uint8_t packet_hmac_data[REPRESENTATIVE_LEN + MARK_LEN + EPOCH_HOUR_LEN + CLIENT_MAX_PAD_LEN + 1];
    memcpy(packet_hmac_data, req->elligator, REPRESENTATIVE_LEN);
    memcpy(packet_hmac_data + REPRESENTATIVE_LEN, req->random_padding, req->padding_len);
    memcpy(packet_hmac_data + REPRESENTATIVE_LEN + req->padding_len, req->elligator_hmac, MARK_LEN);
    if ((real_hour_len = snprintf((char *) packet_hmac_data
                    + REPRESENTATIVE_LEN + req->padding_len + MARK_LEN, EPOCH_HOUR_LEN,
                    "%lu", hr_time)) < 0) {
        goto error;
    }

    size_t hmac_data_len = REPRESENTATIVE_LEN + req->padding_len + MARK_LEN + real_hour_len;

    //dump_hex(packet_hmac_data, hmac_data_len);

    //This is dumb but it works
    if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data, hmac_data_len, req->request_mac)) {
        if ((real_hour_len = snprintf((char *) packet_hmac_data
                        + REPRESENTATIVE_LEN + req->padding_len + MARK_LEN, EPOCH_HOUR_LEN,
                        "%lu", hr_time - 1)) < 0) {
            goto error;
        }
        hmac_data_len = REPRESENTATIVE_LEN + req->padding_len + MARK_LEN + real_hour_len;
        if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data, hmac_data_len, req->request_mac)) {
            if ((real_hour_len = snprintf((char *) packet_hmac_data
                            + REPRESENTATIVE_LEN + req->padding_len + MARK_LEN, EPOCH_HOUR_LEN,
                            "%lu", hr_time + 1)) < 0) {
                goto error;
            }
            hmac_data_len = REPRESENTATIVE_LEN + req->padding_len + MARK_LEN + real_hour_len;
            if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data, hmac_data_len, req->request_mac)) {
                goto error;
            }
        }
    }

    return true;

error:
    return false;
}

static bool validate_server_mac(const struct server_response *resp,
        EVP_PKEY *ntor_keypair,
        const uint8_t identity_digest[static 32]) {
    uint8_t mac_key[32 + 32];
    size_t tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(ntor_keypair, mac_key, &tmp_len)) {
        goto error;
    }
    memcpy(mac_key + 32, identity_digest, 32);

    if (hmac_verify(mac_key, sizeof(mac_key), resp->elligator, REPRESENTATIVE_LEN, resp->elligator_hmac)) {
        goto error;
    }

    uint8_t packet_hmac_data[REPRESENTATIVE_LEN + AUTH_LEN + MARK_LEN + EPOCH_HOUR_LEN + SERVER_MAX_PAD_LEN];
    memcpy(packet_hmac_data, resp->elligator, REPRESENTATIVE_LEN);
    memcpy(packet_hmac_data + REPRESENTATIVE_LEN, resp->auth_tag, AUTH_LEN);
    memcpy(packet_hmac_data + REPRESENTATIVE_LEN + AUTH_LEN, resp->random_padding, resp->padding_len);
    memcpy(packet_hmac_data + REPRESENTATIVE_LEN + AUTH_LEN + resp->padding_len, resp->elligator_hmac, MARK_LEN);

    size_t hmac_data_len = REPRESENTATIVE_LEN + AUTH_LEN + resp->padding_len + MAC_LEN;

    dump_hex(packet_hmac_data, hmac_data_len);

    if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data,
            hmac_data_len, resp->response_mac)) {
        goto error;
    }

    return true;

error:
    return false;
}

int create_client_request(EVP_PKEY *self_keypair,
        EVP_PKEY *ntor_keypair,
        const uint8_t identity_digest[static 32],
        struct client_request *out_req) {

    if (elligator2(self_keypair, out_req->elligator)) {
        goto error;
    }

    out_req->padding_len = rand_interval(CLIENT_MIN_PAD_LEN, CLIENT_MAX_PAD_LEN);
    RAND_bytes(out_req->random_padding, out_req->padding_len);

    uint8_t shared_knowledge[32 + 32];
    size_t tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(ntor_keypair, shared_knowledge, &tmp_len)) {
        goto error;
    }
    memcpy(shared_knowledge + 32, identity_digest, 32);

    if (hmac_gen(shared_knowledge, sizeof(shared_knowledge), out_req->elligator, REPRESENTATIVE_LEN, out_req->elligator_hmac)) {
        goto error;
    }

    //Get the number of hours since epoch
    const uint64_t hr_time = time(NULL) / 3600;

    int real_hour_len;
    if ((real_hour_len = snprintf((char *) out_req->epoch_hours, EPOCH_HOUR_LEN, "%lu", hr_time)) < 0) {
        goto error;
    }

    uint8_t request_mac_data[REPRESENTATIVE_LEN + MARK_LEN + EPOCH_HOUR_LEN + CLIENT_MAX_PAD_LEN];
    memcpy(request_mac_data, out_req->elligator, REPRESENTATIVE_LEN);
    memcpy(request_mac_data + REPRESENTATIVE_LEN, out_req->random_padding, out_req->padding_len);
    memcpy(request_mac_data + REPRESENTATIVE_LEN + out_req->padding_len, out_req->elligator_hmac, MARK_LEN);
    memcpy(request_mac_data + REPRESENTATIVE_LEN + out_req->padding_len + MARK_LEN, out_req->epoch_hours, real_hour_len);

    const size_t hmac_data_len = REPRESENTATIVE_LEN + out_req->padding_len + MARK_LEN + real_hour_len;

    //dump_hex(request_mac_data, hmac_data_len);

    if (hmac_gen(shared_knowledge, sizeof(shared_knowledge), request_mac_data,
                hmac_data_len,
                out_req->request_mac)) {
        goto error;
    }

    return 0;

error:
    OPENSSL_cleanse(out_req, sizeof(*out_req));
    return -1;
}

int create_server_response(EVP_PKEY *ntor_keypair,
        const uint8_t identity_digest[static 32],
        const struct client_request *incoming_req,
        struct server_response *out_resp,
        uint8_t *out_auth,
        uint8_t *out_seed) {
    EVP_PKEY *client_pubkey = NULL;
    uint8_t key_seed[32];
    EVP_PKEY *ephem_key = NULL;
    uint8_t response_mac_key[32 + 32];
    size_t tmp_len = 32;
    uint8_t packet_mac_data[REPRESENTATIVE_LEN + AUTH_LEN + SERVER_MAX_PAD_LEN + MAC_LEN + EPOCH_HOUR_LEN];

    if (!validate_client_mac(incoming_req, ntor_keypair, identity_digest)) {
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

    if (server_ntor(ephem_key, ntor_keypair, client_pubkey, identity_digest, out_resp->auth_tag, key_seed)) {
        goto error;
    }

    out_resp->padding_len = rand_interval(SERVER_MIN_PAD_LEN, SERVER_MAX_PAD_LEN);
    RAND_bytes(out_resp->random_padding, out_resp->padding_len);

    if (!EVP_PKEY_get_raw_public_key(ntor_keypair, response_mac_key, &tmp_len)) {
        goto error;
    }

    memcpy(response_mac_key + 32, identity_digest, 32);

    if (hmac_gen(response_mac_key, sizeof(response_mac_key), out_resp->elligator, 32, out_resp->elligator_hmac)) {
        goto error;
    }

    memcpy(packet_mac_data, out_resp->elligator, REPRESENTATIVE_LEN);
    memcpy(packet_mac_data + REPRESENTATIVE_LEN, out_resp->auth_tag, AUTH_LEN);
    memcpy(packet_mac_data + REPRESENTATIVE_LEN + AUTH_LEN, out_resp->random_padding, out_resp->padding_len);
    memcpy(packet_mac_data + REPRESENTATIVE_LEN + AUTH_LEN + out_resp->padding_len,
            out_resp->elligator_hmac, MAC_LEN);
    memcpy(packet_mac_data + REPRESENTATIVE_LEN + AUTH_LEN + out_resp->padding_len + MAC_LEN,
            incoming_req->epoch_hours, EPOCH_HOUR_LEN);

    size_t packet_hmac_len = REPRESENTATIVE_LEN + AUTH_LEN + out_resp->padding_len + MAC_LEN;

    dump_hex(packet_mac_data, packet_hmac_len);

    if (hmac_gen(response_mac_key, sizeof(response_mac_key), packet_mac_data, packet_hmac_len, out_resp->response_mac)) {
        goto error;
    }

    memcpy(out_auth, out_resp->auth_tag, sizeof(out_resp->auth_tag));
    memcpy(out_seed, key_seed, sizeof(key_seed));

    EVP_PKEY_free(ephem_key);
    return 0;

error:
    EVP_PKEY_free(ephem_key);
    EVP_PKEY_free(client_pubkey);
    OPENSSL_cleanse(out_resp, sizeof(*out_resp));
    return -1;
}

int client_process_server_response(EVP_PKEY *self_keypair,
        EVP_PKEY *ntor_keypair,
        const uint8_t identity_digest[static 32],
        struct server_response *resp,
        uint8_t *out_auth,
        uint8_t *out_seed) {
    uint8_t auth_tag[32];
    uint8_t key_seed[32];

    if (!validate_server_mac(resp, ntor_keypair, identity_digest)) {
        return -1;
    }

    EVP_PKEY *server_pubkey = elligator2_inv(resp->elligator);
    if (server_pubkey == NULL) {
        return -1;
    }

    if (client_ntor(self_keypair, server_pubkey, ntor_keypair, identity_digest, auth_tag, key_seed) == -1) {
        EVP_PKEY_free(server_pubkey);
        return -1;
    }

    if (CRYPTO_memcmp(auth_tag, resp->auth_tag, sizeof(auth_tag)) != 0) {
        EVP_PKEY_free(server_pubkey);
        return -1;
    }

    memcpy(out_auth, auth_tag, sizeof(auth_tag));
    memcpy(out_seed, key_seed, sizeof(key_seed));

    return 0;
}
