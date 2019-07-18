#ifndef COBFS4_ELLIGATOR
#define COBFS4_ELLIGATOR

#if defined(__cplusplus)
extern "C" {
#endif

#include <openssl/evp.h>

unsigned char *elligator2(EVP_PKEY *pkey);
EVP_PKEY *elligator2_inv(unsigned char buffer[32]);

#if defined(__cplusplus)
}
#endif

#endif /* COBFS4_ELLIGATOR */
