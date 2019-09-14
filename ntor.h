#ifndef COBFS4_NTOR
#define COBFS4_NTOR

int server_ntor(EVP_PKEY *ephem_keypair,
        EVP_PKEY *ntor_keypair,
        EVP_PKEY *remote_pubkey,
        const unsigned char identity_digest[static const 32],
        unsigned char out_auth[static const 32],
        unsigned char out_keyseed[static const 32]);

int client_ntor(EVP_PKEY *ephem_keypair,
        EVP_PKEY *remote_pubkey,
        EVP_PKEY *preshared_pubkey,
        const unsigned char identity_digest[static const 32],
        unsigned char out_auth[static const 32],
        unsigned char out_keyseed[static const 32]);

#endif
