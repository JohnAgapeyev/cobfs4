#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "packet.h"
#include "elligator.h"
#include "hmac.h"

/*
 * Modified from:
 * https://stackoverflow.com/a/17554531
 */
uint64_t rand_interval(const uint64_t min, const uint64_t max) {
    uint64_t r;
    const uint64_t range = 1 + max - min;
    const uint64_t buckets = UINT64_MAX / range;
    const uint64_t limit = buckets * range;

    /* Create equal size buckets all in a row, then fire randomly towards
     * the buckets until you land in one of them. All buckets are equally
     * likely. If you land off the end of the line of buckets, try again. */
    do {
        RAND_bytes((unsigned char *) &r, sizeof(r));
    } while (r >= limit);

    return min + (r / buckets);
}

int create_client_request(const EVP_PKEY * const self_keypair,
        const uint8_t * const shared_knowledge,
        const size_t shared_len,
        struct client_request *out_req) {

    if (elligator2(self_keypair, out_req->elligator)) {
        goto error;
    }

    const uint64_t padding_len = rand_interval(CLIENT_MIN_PAD_LEN, CLIENT_MAX_PAD_LEN);
    uint8_t random_padding[CLIENT_MAX_PAD_LEN];
    RAND_bytes(random_padding, padding_len);

    memcpy(out_req->random_padding, random_padding, padding_len);

    if (hmac_gen(shared_knowledge, shared_len, out_req->elligator, REPRESENTATIVE_LEN, out_req->elligator_hmac)) {
        goto error;
    }

    //Get the number of hours since epoch
    const uint64_t sec_time = time(NULL) / 3600;

    int real_hour_len;
    if ((real_hour_len = snprintf((char *) out_req->epoch_hours, EPOCH_HOUR_LEN, "%lu%c", sec_time, '\0')) < 0) {
        goto error;
    }

    uint8_t request_mac_data[REPRESENTATIVE_LEN + MARK_LEN + EPOCH_HOUR_LEN + CLIENT_MAX_PAD_LEN];
    memcpy(request_mac_data, out_req->elligator, REPRESENTATIVE_LEN);
    memcpy(request_mac_data + REPRESENTATIVE_LEN, out_req->random_padding, padding_len);
    memcpy(request_mac_data + REPRESENTATIVE_LEN + padding_len, out_req->elligator_hmac, MARK_LEN);
    memcpy(request_mac_data + REPRESENTATIVE_LEN + padding_len + MARK_LEN, out_req->epoch_hours, real_hour_len);

    if (hmac_gen(shared_knowledge, shared_len, request_mac_data,
                REPRESENTATIVE_LEN + padding_len + MARK_LEN + real_hour_len,
                out_req->request_mac)) {
        goto error;
    }

    return 0;

error:
    OPENSSL_cleanse(out_req, sizeof(*out_req));
    return -1;
}

