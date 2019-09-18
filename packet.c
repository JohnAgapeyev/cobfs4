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

static bool validate_client_mac(const struct client_request *req) {
    (void)req;
    return true;
}

int create_client_request(EVP_PKEY *self_keypair,
        const uint8_t *shared_knowledge,
        const size_t shared_len,
        struct client_request *out_req) {

    if (elligator2(self_keypair, out_req->elligator)) {
        goto error;
    }

    out_req->padding_len = rand_interval(CLIENT_MIN_PAD_LEN, CLIENT_MAX_PAD_LEN);
    RAND_bytes(out_req->random_padding, out_req->padding_len);

    if (hmac_gen(shared_knowledge, shared_len, out_req->elligator, REPRESENTATIVE_LEN, out_req->elligator_hmac)) {
        goto error;
    }

    //Get the number of hours since epoch
    const uint64_t hr_time = time(NULL) / 3600;

    int real_hour_len;
    if ((real_hour_len = snprintf((char *) out_req->epoch_hours, EPOCH_HOUR_LEN, "%lu%c", hr_time, '\0')) < 0) {
        goto error;
    }

    uint8_t request_mac_data[REPRESENTATIVE_LEN + MARK_LEN + EPOCH_HOUR_LEN + CLIENT_MAX_PAD_LEN];
    memcpy(request_mac_data, out_req->elligator, REPRESENTATIVE_LEN);
    memcpy(request_mac_data + REPRESENTATIVE_LEN, out_req->random_padding, out_req->padding_len);
    memcpy(request_mac_data + REPRESENTATIVE_LEN + out_req->padding_len, out_req->elligator_hmac, MARK_LEN);
    memcpy(request_mac_data + REPRESENTATIVE_LEN + out_req->padding_len + MARK_LEN, out_req->epoch_hours, real_hour_len);

    if (hmac_gen(shared_knowledge, shared_len, request_mac_data,
                REPRESENTATIVE_LEN + out_req->padding_len + MARK_LEN + real_hour_len,
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
        struct server_response *out_resp) {
    if (!validate_client_mac(incoming_req)) {
        return -1;
    }

    uint8_t key_seed[32];
    EVP_PKEY *ephem_key = ecdh_key_alloc();
    if (!ephem_key) {
        return -1;
    }

    if (elligator2(ephem_key, out_resp->elligator)) {
        goto error;
    }

    EVP_PKEY *client_pubkey = elligator2_inv(incoming_req->elligator);
    if (!client_pubkey) {
        goto error;
    }

    if (server_ntor(ephem_key, ntor_keypair, client_pubkey, identity_digest, out_resp->auth_tag, key_seed)) {
        goto error;
    }

    out_resp->padding_len = rand_interval(SERVER_MIN_PAD_LEN, SERVER_MAX_PAD_LEN);
    RAND_bytes(out_resp->random_padding, out_resp->padding_len);

    uint8_t response_mac_key[32 + 32];

    size_t tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(ntor_keypair, response_mac_key, &tmp_len)) {
        goto error;
    }

    memcpy(response_mac_key + 32, out_resp->elligator, 32);

    if (hmac_gen(response_mac_key, sizeof(response_mac_key), out_resp->elligator, 32, out_resp->elligator_hmac)) {
        goto error;
    }

    //Generate response mac here


    EVP_PKEY_free(ephem_key);
    return 0;

error:
    EVP_PKEY_free(ephem_key);
    EVP_PKEY_free(client_pubkey);
    OPENSSL_cleanse(out_resp, sizeof(*out_resp));
    return -1;
}
