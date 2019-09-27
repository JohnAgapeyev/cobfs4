#ifndef COBFS4_PACKET
#define COBFS4_PACKET

#include <stdint.h>

#define MAX_HANDSHAKE_SIZE 8192
#define MARK_LEN 32
#define MAC_LEN 32
#define TAG_LEN 16
#define REPRESENTATIVE_LEN 32
#define AUTH_LEN 32
#define INLINE_SEED_FRAME_LEN 45
#define SERVER_HANDSHAKE_LEN 96
#define SERVER_MIN_PAD_LEN INLINE_SEED_FRAME_LEN
#define SERVER_MAX_PAD_LEN 8096
#define CLIENT_HANDSHAKE_LEN 64
#define CLIENT_MIN_PAD_LEN 85
#define CLIENT_MAX_PAD_LEN 8128

//Normally decimal epoch hours are 6 digits, so this gives me leeway
#define EPOCH_HOUR_LEN 8

typedef enum {
    TYPE_PAYLOAD = 0,
    TYPE_PRNG_SEED = 1
} packet_type_t;

struct client_request {
    uint8_t elligator[REPRESENTATIVE_LEN];
    uint8_t elligator_hmac[MARK_LEN];
    uint8_t epoch_hours[EPOCH_HOUR_LEN];
    uint8_t request_mac[MAC_LEN];
    uint64_t padding_len;
    uint8_t random_padding[CLIENT_MAX_PAD_LEN];
};

struct server_response {
    uint8_t elligator[REPRESENTATIVE_LEN];
    uint8_t auth_tag[AUTH_LEN];
    uint8_t elligator_hmac[MARK_LEN];
    uint8_t response_mac[MAC_LEN];
    uint64_t padding_len;
    uint8_t random_padding[SERVER_MAX_PAD_LEN];
};

struct data_packet {
    uint16_t frame_len;
    uint8_t tag[TAG_LEN];
    uint8_t type;
    uint16_t payload_len;
    uint8_t data[];
};

int create_client_request(EVP_PKEY *self_keypair,
        EVP_PKEY *ntor_keypair,
        const uint8_t identity_digest[static 32],
        const size_t shared_len,
        struct client_request *out_req);

int create_server_response(EVP_PKEY *ntor_keypair,
        const uint8_t identity_digest[static 32],
        const struct client_request *incoming_req,
        struct server_response *out_resp);

#endif /* COBFS4_PACKET */
