#ifndef COBFS4_ECDH
#define COBFS4_ECDH

EVP_PKEY *ecdh_key_alloc(void);

int ecdh_derive(EVP_PKEY *self_keypair, EVP_PKEY *remote_pub_key, uint8_t out_buffer[static 32]);

#endif
