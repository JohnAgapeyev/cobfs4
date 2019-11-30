#ifndef COBFS4_NTOR
#define COBFS4_NTOR

#include "constants.h"

struct shared_data {
    EVP_PKEY * restrict ntor;
    uint8_t identity_digest[COBFS4_HASH_LEN];
};

int server_ntor(EVP_PKEY * restrict ephem_keypair,
        EVP_PKEY * restrict remote_pubkey,
        const struct shared_data * restrict shared,
        uint8_t out_auth[static restrict COBFS4_AUTH_LEN],
        uint8_t out_keyseed[static restrict COBFS4_SEED_LEN]);

int client_ntor(EVP_PKEY * restrict ephem_keypair,
        EVP_PKEY * restrict remote_pubkey,
        const struct shared_data * restrict shared,
        uint8_t out_auth[static restrict COBFS4_AUTH_LEN],
        uint8_t out_keyseed[static restrict COBFS4_SEED_LEN]);

#endif
