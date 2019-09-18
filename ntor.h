#ifndef COBFS4_NTOR
#define COBFS4_NTOR

int server_ntor(EVP_PKEY *ephem_keypair,
        EVP_PKEY *ntor_keypair,
        EVP_PKEY *remote_pubkey,
        const uint8_t identity_digest[static 32],
        uint8_t out_auth[static 32],
        uint8_t out_keyseed[static 32]);

int client_ntor(EVP_PKEY *ephem_keypair,
        EVP_PKEY *remote_pubkey,
        EVP_PKEY *preshared_pubkey,
        const uint8_t identity_digest[static 32],
        uint8_t out_auth[static 32],
        uint8_t out_keyseed[static 32]);

#endif
