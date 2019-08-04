#ifndef COBFS4_PACKET
#define COBFS4_PACKET

#include <stdint.h>

#define MAX_HANDSHAKE_SIZE 8192
#define MARK_LEN 16
#define MAC_LEN 16
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
    uint8_t random_padding[CLIENT_MAX_PAD_LEN];
};

struct server_response {
    uint8_t elligator[REPRESENTATIVE_LEN];
    uint8_t auth_tag[AUTH_LEN];
    uint8_t elligator_hmac[MARK_LEN];
    uint8_t epoch_hours[EPOCH_HOUR_LEN];
    uint8_t request_mac[MAC_LEN];
    uint8_t random_padding[SERVER_MAX_PAD_LEN];
};

struct data_packet {
    uint16_t frame_len;
    uint8_t tag[TAG_LEN];
    uint8_t type;
    uint16_t payload_len;
    uint8_t data[];
};

int create_client_request(const EVP_PKEY * const self_keypair,
        const uint8_t * const shared_knowledge,
        const size_t shared_len,
        struct client_request *out_req);

#endif /* COBFS4_PACKET */
