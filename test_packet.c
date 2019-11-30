#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "packet.h"
#include "ecdh.h"
#include "ntor.h"
#include "elligator.h"
#include "constants.h"

//Stand-in for a real digest, since the value doesn't matter at all
static const uint8_t *identity_digest = (const uint8_t *) "012345678901234567890123456789ab";

void test_handshake(void) {
    int good = 0;
    int bad = 0;
    int i = 0;
    for (i = 0; i < 10000; ++i) {
        EVP_PKEY *client = ecdh_key_alloc();

        uint8_t tmp_elligator[COBFS4_ELLIGATOR_LEN];

        uint8_t client_tag[COBFS4_AUTH_LEN];
        uint8_t client_seed[COBFS4_SEED_LEN];
        uint8_t server_tag[COBFS4_AUTH_LEN];
        uint8_t server_seed[COBFS4_SEED_LEN];

        struct client_request req;
        struct server_response resp;

        struct shared_data shared;
        shared.ntor = ecdh_key_alloc();
        memcpy(&shared.identity_digest, identity_digest, strlen((char *) identity_digest));

        while (elligator2(client, tmp_elligator) == -1) {
            EVP_PKEY_free(client);
            client = ecdh_key_alloc();
        }

        if (create_client_request(client, &shared, &req) == -1) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client);
            continue;
        }

        if (create_server_response(&shared, &req, &resp, server_tag, server_seed) == -1) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client);
            continue;
        }

        if (client_process_server_response(client, &shared, &resp, client_tag, client_seed) == -1) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client);
            continue;
        }

        if (memcmp(client_tag, server_tag, sizeof(client_tag)) != 0) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client);
            continue;
        }

        if (memcmp(client_seed, server_seed, sizeof(client_seed)) != 0) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client);
            continue;
        }

        ++good;
        EVP_PKEY_free(shared.ntor);
        EVP_PKEY_free(client);
    }

    printf("Packet handshake testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
