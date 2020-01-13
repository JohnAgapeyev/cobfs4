#ifndef COBFS4_PACKET
#define COBFS4_PACKET

#include <stdint.h>
#include <limits.h>

#include "constants.h"
#include "ntor.h"

struct client_request {
    uint8_t elligator[COBFS4_ELLIGATOR_LEN];
    uint8_t elligator_hmac[COBFS4_HMAC_LEN];
    uint8_t epoch_hours[COBFS4_EPOCH_HOUR_LEN + 1]; //Add room for null from snprintf
    uint8_t request_mac[COBFS4_HMAC_LEN];
    uint64_t padding_len;
    uint8_t random_padding[COBFS4_CLIENT_MAX_PAD_LEN];
};

struct server_response {
    uint8_t elligator[COBFS4_ELLIGATOR_LEN];
    uint8_t auth_tag[COBFS4_AUTH_LEN];
    uint8_t elligator_hmac[COBFS4_HMAC_LEN];
    uint8_t response_mac[COBFS4_HMAC_LEN];
    uint8_t seed_frame[COBFS4_INLINE_SEED_FRAME_LEN];
    uint64_t padding_len;
    uint8_t random_padding[COBFS4_SERVER_MAX_PAD_LEN];
};

struct stretched_key {
    uint8_t server2client_key[COBFS4_SECRET_KEY_LEN];
    uint8_t server2client_nonce_prefix[COBFS4_NONCE_PREFIX_LEN];
    uint8_t server2client_siphash_key[COBFS4_SIPHASH_KEY_LEN];
    uint8_t server2client_siphash_iv[COBFS4_SIPHASH_IV_LEN];

    uint8_t client2server_key[COBFS4_SECRET_KEY_LEN];
    uint8_t client2server_nonce_prefix[COBFS4_NONCE_PREFIX_LEN];
    uint8_t client2server_siphash_key[COBFS4_SIPHASH_KEY_LEN];
    uint8_t client2server_siphash_iv[COBFS4_SIPHASH_IV_LEN];
};

int create_client_request(EVP_PKEY * restrict self_keypair,
        const struct shared_data * restrict shared,
        struct client_request * restrict out_req);

int create_server_response(const struct shared_data * restrict shared,
        const struct client_request * restrict incoming_req,
        const uint8_t random_seed[static restrict COBFS4_SERVER_TIMING_SEED_LEN],
        struct server_response * restrict out_resp,
        struct stretched_key * restrict out_keys);

int client_process_server_response(EVP_PKEY * restrict self_keypair,
        const struct shared_data * restrict shared,
        struct server_response * restrict resp,
        uint8_t out_server_timing_seed[static restrict COBFS4_SERVER_TIMING_SEED_LEN],
        struct stretched_key * restrict out_keys);

#endif /* COBFS4_PACKET */
