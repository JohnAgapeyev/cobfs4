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
#include "utils.h"
#include "kdf.h"

static const uint8_t *expand_mesg = (uint8_t *) "ntor-curve25519-sha256-1:key_expand";
static size_t expand_mesg_len = 35;
static const uint8_t *expand_salt = (uint8_t *) "ntor-curve25519-sha256-1:key_extract";
static size_t expand_salt_len = 36;

static bool validate_client_mac(const struct client_request * restrict req,
        const struct shared_data * restrict shared, uint64_t *out_hrs) {
    uint8_t mac_key[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    if (make_shared_data(shared, mac_key) != COBFS4_OK) {
        goto error;
    }

    if (hmac_verify(mac_key, sizeof(mac_key), req->elligator, COBFS4_ELLIGATOR_LEN, req->elligator_hmac) != COBFS4_OK) {
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

    const size_t hmac_data_len = COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN + real_hour_len;

    if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data, hmac_data_len, req->request_mac) == COBFS4_OK) {
        *out_hrs = hr_time;
        goto done;
    }
    if (snprintf((char *) packet_hmac_data
                + COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN, COBFS4_EPOCH_HOUR_LEN,
                "%lu", hr_time - 1) < 0) {
        goto error;
    }
    if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data, hmac_data_len, req->request_mac) == COBFS4_OK) {
        *out_hrs = hr_time - 1;
        goto done;
    }
    if (snprintf((char *) packet_hmac_data
                + COBFS4_ELLIGATOR_LEN + req->padding_len + COBFS4_HMAC_LEN, COBFS4_EPOCH_HOUR_LEN,
                "%lu", hr_time + 1) < 0) {
        goto error;
    }
    if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data, hmac_data_len, req->request_mac) == COBFS4_OK) {
        *out_hrs = hr_time + 1;
        goto done;
    }
    goto error;

done:
    return true;
error:
    return false;
}

static bool validate_server_mac(const struct server_response * restrict resp,
        const struct shared_data * restrict shared) {

    uint8_t mac_key[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    uint8_t packet_hmac_data[COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN
        + COBFS4_HMAC_LEN + COBFS4_SERVER_MAX_PAD_LEN + COBFS4_EPOCH_HOUR_LEN];

    if (make_shared_data(shared, mac_key) != COBFS4_OK) {
        goto error;
    }

    if (hmac_verify(mac_key, sizeof(mac_key), resp->elligator, COBFS4_ELLIGATOR_LEN, resp->elligator_hmac) != COBFS4_OK) {
        goto error;
    }

    memcpy(packet_hmac_data, resp->elligator, COBFS4_ELLIGATOR_LEN);
    memcpy(packet_hmac_data + COBFS4_ELLIGATOR_LEN, resp->auth_tag, COBFS4_AUTH_LEN);
    memcpy(packet_hmac_data + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN, resp->random_padding, resp->padding_len);
    memcpy(packet_hmac_data + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len, resp->elligator_hmac, COBFS4_HMAC_LEN);

    const uint64_t hr_time = time(NULL) / 3600;
    int real_hour_len;

    if ((real_hour_len = snprintf((char *) packet_hmac_data
                    + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len + COBFS4_HMAC_LEN,
                    COBFS4_EPOCH_HOUR_LEN,
                    "%lu", hr_time)) < 0) {
        goto error;
    }

    const size_t actual_data_len = COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len + COBFS4_HMAC_LEN + real_hour_len;

    if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data,
            actual_data_len, resp->response_mac) == COBFS4_OK) {
        goto done;
    }
    if (snprintf((char *) packet_hmac_data
                + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len + COBFS4_HMAC_LEN,
                COBFS4_EPOCH_HOUR_LEN,
                "%lu", hr_time - 1) < 0) {
        goto error;
    }
    if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data,
                actual_data_len, resp->response_mac) == COBFS4_OK) {
        goto done;
    }
    if (snprintf((char *) packet_hmac_data
                + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + resp->padding_len + COBFS4_HMAC_LEN,
                COBFS4_EPOCH_HOUR_LEN,
                "%lu", hr_time + 1) < 0) {
        goto error;
    }
    if (hmac_verify(mac_key, sizeof(mac_key), packet_hmac_data,
                actual_data_len, resp->response_mac) == COBFS4_OK) {
        goto done;
    }
    goto error;

done:
    return true;
error:
    return false;
}

enum cobfs4_return_code create_client_request(EVP_PKEY * restrict self_keypair,
        const struct shared_data * restrict shared,
        struct client_request * restrict out_req) {
    uint8_t mac_key[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    uint8_t request_mac_data[COBFS4_ELLIGATOR_LEN + COBFS4_HMAC_LEN
        + COBFS4_EPOCH_HOUR_LEN + COBFS4_CLIENT_MAX_PAD_LEN];

    if (self_keypair == NULL) {
        goto error;
    }
    if (shared == NULL) {
        goto error;
    }
    if (out_req == NULL) {
        goto error;
    }

    if (elligator2_inv(self_keypair, out_req->elligator) != COBFS4_OK) {
        goto error;
    }

    out_req->padding_len = rand_interval(COBFS4_CLIENT_MIN_PAD_LEN, COBFS4_CLIENT_MAX_PAD_LEN);
    if (out_req->padding_len > COBFS4_CLIENT_MAX_PAD_LEN) {
        goto error;
    }
    if (RAND_bytes(out_req->random_padding, out_req->padding_len) != 1) {
        goto error;
    }

    if (make_shared_data(shared, mac_key) != COBFS4_OK) {
        goto error;
    }

    if (hmac_gen(mac_key, sizeof(mac_key), out_req->elligator, COBFS4_ELLIGATOR_LEN, out_req->elligator_hmac) != COBFS4_OK) {
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

    if (hmac_gen(mac_key, sizeof(mac_key), request_mac_data,
                hmac_data_len,
                out_req->request_mac) != COBFS4_OK) {
        goto error;
    }
    return COBFS4_OK;

error:
    OPENSSL_cleanse(out_req, sizeof(*out_req));
    return COBFS4_ERROR;
}

enum cobfs4_return_code create_server_response(const struct shared_data * restrict shared,
        const struct client_request * restrict incoming_req,
        const uint8_t random_seed[static restrict COBFS4_SERVER_TIMING_SEED_LEN],
        struct server_response * restrict out_resp,
        struct stretched_key * restrict out_keys) {
    EVP_PKEY *client_pubkey = NULL;
    EVP_PKEY *ephem_key = NULL;
    uint8_t mac_key[COBFS4_PUBKEY_LEN + COBFS4_HASH_LEN];
    uint8_t packet_mac_data[COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN
        + COBFS4_SERVER_MAX_PAD_LEN + COBFS4_HMAC_LEN + COBFS4_EPOCH_HOUR_LEN];
    struct ntor_output ntor;
    uint8_t seed_iv[COBFS4_IV_LEN];
    uint8_t epoch_hours[COBFS4_EPOCH_HOUR_LEN + 1];
    uint64_t client_hrs;

    if (shared == NULL) {
        goto error;
    }
    if (incoming_req == NULL) {
        goto error;
    }
    if (random_seed == NULL) {
        goto error;
    }
    if (out_resp == NULL) {
        goto error;
    }
    if (out_keys == NULL) {
        goto error;
    }

    if (!validate_client_mac(incoming_req, shared, &client_hrs)) {
        goto error;
    }

    ephem_key = ecdh_key_alloc();
    if (!ephem_key) {
        goto error;
    }

    client_pubkey = elligator2(incoming_req->elligator);
    if (!client_pubkey) {
        goto error;
    }

    if (server_ntor(ephem_key, client_pubkey, shared, &ntor) != COBFS4_OK) {
        goto error;
    }

    if (elligator2_inv(ephem_key, out_resp->elligator) != COBFS4_OK) {
        goto error;
    }

    memcpy(out_resp->auth_tag, &ntor.auth_tag, COBFS4_AUTH_LEN);
    out_resp->padding_len = rand_interval(COBFS4_SERVER_MIN_PAD_LEN, COBFS4_SERVER_MAX_PAD_LEN);
    if (out_resp->padding_len > COBFS4_SERVER_MAX_PAD_LEN) {
        goto error;
    }
    if (RAND_bytes(out_resp->random_padding, out_resp->padding_len) != 1) {
        goto error;
    }

    if (make_shared_data(shared, mac_key) != COBFS4_OK) {
        goto error;
    }

    if (hmac_gen(mac_key, sizeof(mac_key), out_resp->elligator, COBFS4_ELLIGATOR_LEN, out_resp->elligator_hmac) != COBFS4_OK) {
        goto error;
    }

    int real_hour_len;
    if ((real_hour_len = snprintf((char *) epoch_hours, COBFS4_EPOCH_HOUR_LEN, "%lu", client_hrs)) < 0) {
        goto error;
    }

    memcpy(packet_mac_data, out_resp->elligator, COBFS4_ELLIGATOR_LEN);
    memcpy(packet_mac_data + COBFS4_ELLIGATOR_LEN, &ntor.auth_tag, COBFS4_AUTH_LEN);
    memcpy(packet_mac_data + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN, out_resp->random_padding, out_resp->padding_len);
    memcpy(packet_mac_data + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + out_resp->padding_len,
            out_resp->elligator_hmac, COBFS4_HMAC_LEN);
    memcpy(packet_mac_data + COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN + out_resp->padding_len + COBFS4_HMAC_LEN,
            epoch_hours, COBFS4_EPOCH_HOUR_LEN);

    const size_t packet_hmac_len = COBFS4_ELLIGATOR_LEN + COBFS4_AUTH_LEN
        + out_resp->padding_len + COBFS4_HMAC_LEN + COBFS4_EPOCH_HOUR_LEN;

    if (hmac_gen(mac_key, sizeof(mac_key), packet_mac_data, packet_hmac_len, out_resp->response_mac) != COBFS4_OK) {
        goto error;
    }

    if (hkdf(expand_mesg, expand_mesg_len, expand_salt, expand_salt_len, ntor.key_seed, sizeof(ntor.key_seed),
                (uint8_t *) out_keys, sizeof(*out_keys)) != COBFS4_OK) {
        goto error;
    }

    memcpy(seed_iv, out_keys->server2client_nonce_prefix, sizeof(out_keys->server2client_nonce_prefix));
    memset(seed_iv + sizeof(out_keys->server2client_nonce_prefix), 0,
            COBFS4_IV_LEN - sizeof(out_keys->server2client_nonce_prefix));
    if (make_frame(random_seed, COBFS4_SERVER_TIMING_SEED_LEN, 0, TYPE_PRNG_SEED,
                out_keys->server2client_key, seed_iv, out_resp->seed_frame) != COBFS4_OK) {
        goto error;
    }

    EVP_PKEY_free(ephem_key);
    EVP_PKEY_free(client_pubkey);
    OPENSSL_cleanse(&ntor, sizeof(ntor));
    OPENSSL_cleanse(seed_iv, sizeof(seed_iv));
    return COBFS4_OK;

error:
    if (ephem_key) {
        EVP_PKEY_free(ephem_key);
    }
    if (client_pubkey) {
        EVP_PKEY_free(client_pubkey);
    }
    OPENSSL_cleanse(out_resp, sizeof(*out_resp));
    OPENSSL_cleanse(&ntor, sizeof(ntor));
    OPENSSL_cleanse(seed_iv, sizeof(seed_iv));
    return COBFS4_ERROR;
}

enum cobfs4_return_code client_process_server_response(EVP_PKEY * restrict self_keypair,
        const struct shared_data * restrict shared,
        struct server_response * restrict resp,
        uint8_t out_server_timing_seed[static restrict COBFS4_SERVER_TIMING_SEED_LEN],
        struct stretched_key * restrict out_keys) {
    struct ntor_output ntor;
    uint8_t seed_iv[COBFS4_IV_LEN];
    enum frame_type type;
    uint16_t plain_len;

    if (self_keypair == NULL) {
        goto error;
    }
    if (shared == NULL) {
        goto error;
    }
    if (resp == NULL) {
        goto error;
    }
    if (out_server_timing_seed == NULL) {
        goto error;
    }
    if (out_keys == NULL) {
        goto error;
    }

    if (!validate_server_mac(resp, shared)) {
        goto error;
    }

    EVP_PKEY *server_pubkey = elligator2(resp->elligator);
    if (server_pubkey == NULL) {
        goto error;
    }

    if (client_ntor(self_keypair, server_pubkey, shared, &ntor) != COBFS4_OK) {
        goto error;
    }

    if (CRYPTO_memcmp(&ntor.auth_tag, resp->auth_tag, sizeof(COBFS4_AUTH_LEN)) != 0) {
        goto error;
    }

    if (hkdf(expand_mesg, expand_mesg_len, expand_salt, expand_salt_len, ntor.key_seed, sizeof(ntor.key_seed),
                (uint8_t *) out_keys, sizeof(*out_keys)) != COBFS4_OK) {
        goto error;
    }

    memcpy(seed_iv, out_keys->server2client_nonce_prefix, sizeof(out_keys->server2client_nonce_prefix));
    memset(seed_iv + sizeof(out_keys->server2client_nonce_prefix), 0,
            COBFS4_IV_LEN - sizeof(out_keys->server2client_nonce_prefix));
    if (decrypt_frame(resp->seed_frame, COBFS4_INLINE_SEED_FRAME_LEN,
                out_keys->server2client_key, seed_iv,
                out_server_timing_seed, &plain_len, &type) != COBFS4_OK) {
        goto error;
    }

    if (plain_len != COBFS4_SERVER_TIMING_SEED_LEN) {
        goto error;
    }

    //Normally we ignore unknown types, but in the handshake seed frame?
    //I have no idea how to ignore such dissonance
    if (type != TYPE_PRNG_SEED) {
        goto error;
    }
    EVP_PKEY_free(server_pubkey);
    OPENSSL_cleanse(&ntor, sizeof(ntor));
    return COBFS4_OK;

error:
    if (server_pubkey) {
        EVP_PKEY_free(server_pubkey);
    }
    OPENSSL_cleanse(&ntor, sizeof(ntor));
    return COBFS4_ERROR;
}
