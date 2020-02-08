#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "packet.h"
#include "ecdh.h"
#include "elligator.h"
#include "constants.h"

//Stand-in for a real digest, since the value doesn't matter at all
static const uint8_t *identity_digest = (const uint8_t *) "012345678901234567890123456789ab";

void test_handshake(void) {
    int good = 0;
    int bad = 0;
    int i = 0;
    for (i = 0; i < TEST_CASE_COUNT; ++i) {
        EVP_PKEY *client_key = ecdh_key_alloc();

        uint8_t server_seed[COBFS4_SERVER_TIMING_SEED_LEN];
        RAND_bytes(server_seed, sizeof(server_seed));

        uint8_t recv_seed[COBFS4_SERVER_TIMING_SEED_LEN];

        struct stretched_key client;
        struct stretched_key server;

        struct client_request req;
        struct server_response resp;

        struct shared_data shared;
        shared.ntor = ecdh_key_alloc();
        memcpy(&shared.identity_digest, identity_digest, strlen((char *) identity_digest));

        if (create_client_request(client_key, &shared, &req) == -1) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client_key);
            continue;
        }

        if (create_server_response(&shared, &req, server_seed, &resp, &server) == -1) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client_key);
            continue;
        }

        if (client_process_server_response(client_key, &shared, &resp, recv_seed, &client) == -1) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client_key);
            continue;
        }

        if (memcmp(&client, &server, sizeof(client)) != 0) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client_key);
            continue;
        }

        if (memcmp(server_seed, recv_seed, sizeof(server_seed)) != 0) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client_key);
            continue;
        }

        ++good;
        EVP_PKEY_free(shared.ntor);
        EVP_PKEY_free(client_key);
    }

    printf("Packet handshake testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
