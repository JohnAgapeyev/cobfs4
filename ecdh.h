#ifndef COBFS4_ECDH
#define COBFS4_ECDH

EVP_PKEY *ecdh_key_alloc(void);

int ecdh_derive(EVP_PKEY *self_keypair, EVP_PKEY *remote_pub_key, unsigned char out_buffer[static const 32]);

#endif
