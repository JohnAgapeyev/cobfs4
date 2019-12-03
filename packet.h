#ifndef COBFS4_PACKET
#define COBFS4_PACKET

#include <stdint.h>

#include "constants.h"
#include "ntor.h"

typedef enum {
    TYPE_PAYLOAD = 0,
    TYPE_PRNG_SEED = 1
} packet_type_t;

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
    uint64_t padding_len;
    uint8_t random_padding[COBFS4_SERVER_MAX_PAD_LEN];
};

struct data_packet {
    uint16_t frame_len;
    uint8_t tag[COBFS4_TAG_LEN];
    uint8_t type;
    uint16_t payload_len;
    uint8_t data[];
};

int create_client_request(EVP_PKEY * restrict self_keypair,
        const struct shared_data * restrict shared,
        struct client_request * restrict out_req);

int create_server_response(const struct shared_data * restrict shared,
        const struct client_request * restrict incoming_req,
        struct server_response * restrict out_resp,
        struct ntor_output * restrict out_ntor);

int client_process_server_response(EVP_PKEY * restrict self_keypair,
        const struct shared_data * restrict shared,
        struct server_response * restrict resp,
        struct ntor_output * restrict out_ntor);

#endif /* COBFS4_PACKET */
