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
        EVP_PKEY *client_key = ecdh_key_alloc();

        uint8_t tmp_elligator[COBFS4_ELLIGATOR_LEN];

        struct ntor_output client;
        struct ntor_output server;

        struct client_request req;
        struct server_response resp;

        struct shared_data shared;
        shared.ntor = ecdh_key_alloc();
        memcpy(&shared.identity_digest, identity_digest, strlen((char *) identity_digest));

        while (elligator2(client_key, tmp_elligator) == -1) {
            EVP_PKEY_free(client_key);
            client_key = ecdh_key_alloc();
        }

        if (create_client_request(client_key, &shared, &req) == -1) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client_key);
            continue;
        }

        if (create_server_response(&shared, &req, &resp, &server) == -1) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client_key);
            continue;
        }

        if (client_process_server_response(client_key, &shared, &resp, &client) == -1) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client_key);
            continue;
        }

        if (memcmp(client.auth_tag, server.auth_tag, COBFS4_AUTH_LEN) != 0) {
            ++bad;
            EVP_PKEY_free(shared.ntor);
            EVP_PKEY_free(client_key);
            continue;
        }

        if (memcmp(client.key_seed, server.key_seed, COBFS4_SEED_LEN) != 0) {
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
