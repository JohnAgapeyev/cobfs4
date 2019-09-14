#ifndef COBFS4_ELLIGATOR
#define COBFS4_ELLIGATOR

#include <openssl/evp.h>

int elligator2(const EVP_PKEY * const pkey, unsigned char out_elligator[static const 32]);
EVP_PKEY *elligator2_inv(const unsigned char buffer[static const 32]);

#endif /* COBFS4_ELLIGATOR */
