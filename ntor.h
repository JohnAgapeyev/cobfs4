#ifndef COBFS4_NTOR
#define COBFS4_NTOR

#include "constants.h"

int server_ntor(EVP_PKEY * restrict ephem_keypair,
        EVP_PKEY * restrict remote_pubkey,
        EVP_PKEY * restrict ntor_keypair,
        const uint8_t identity_digest[static restrict COBFS4_HASH_LEN],
        uint8_t out_auth[static restrict COBFS4_AUTH_LEN],
        uint8_t out_keyseed[static restrict COBFS4_SEED_LEN]);

int client_ntor(EVP_PKEY * restrict ephem_keypair,
        EVP_PKEY * restrict remote_pubkey,
        EVP_PKEY * restrict ntor_pubkey,
        const uint8_t identity_digest[static restrict COBFS4_HASH_LEN],
        uint8_t out_auth[static restrict COBFS4_AUTH_LEN],
        uint8_t out_keyseed[static restrict COBFS4_SEED_LEN]);

#endif
