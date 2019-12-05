#ifndef COBFS4_ELLIGATOR
#define COBFS4_ELLIGATOR

#include <openssl/evp.h>

#include "constants.h"

int elligator2(const EVP_PKEY * restrict pkey, uint8_t out_elligator[static restrict COBFS4_ELLIGATOR_LEN]);
EVP_PKEY *elligator2_inv(const uint8_t buffer[static restrict COBFS4_ELLIGATOR_LEN]);

#endif /* COBFS4_ELLIGATOR */
