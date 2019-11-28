#ifndef COBFS4_ECDH
#define COBFS4_ECDH

#include "constants.h"

EVP_PKEY *ecdh_key_alloc(void);

int ecdh_derive(EVP_PKEY * restrict self_keypair, EVP_PKEY * restrict remote_pub_key,
        uint8_t out_buffer[static restrict COBFS4_PUBKEY_LEN]);

#endif
