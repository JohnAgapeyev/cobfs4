#ifndef COBFS4_ELLIGATOR
#define COBFS4_ELLIGATOR

#include <openssl/evp.h>

int elligator2(const EVP_PKEY * const pkey, uint8_t out_elligator[static const 32]);
EVP_PKEY *elligator2_inv(const uint8_t buffer[static const 32]);

#endif /* COBFS4_ELLIGATOR */
