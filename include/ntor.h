#ifndef COBFS4_NTOR
#define COBFS4_NTOR

#include "constants.h"

struct shared_data {
    EVP_PKEY * restrict ntor;
    uint8_t identity_digest[COBFS4_HASH_LEN];
};

struct ntor_output {
    uint8_t auth_tag[COBFS4_AUTH_LEN];
    uint8_t key_seed[COBFS4_SEED_LEN];
};

enum cobfs4_return_code server_ntor(EVP_PKEY * restrict ephem_keypair,
        EVP_PKEY * restrict remote_pubkey,
        const struct shared_data * restrict shared,
        struct ntor_output * restrict out);

enum cobfs4_return_code client_ntor(EVP_PKEY * restrict ephem_keypair,
        EVP_PKEY * restrict remote_pubkey,
        const struct shared_data * restrict shared,
        struct ntor_output * restrict out);

#endif
