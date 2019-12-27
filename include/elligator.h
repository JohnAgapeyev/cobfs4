#ifndef COBFS4_ELLIGATOR
#define COBFS4_ELLIGATOR

#include <stdbool.h>
#include <openssl/evp.h>

#include "constants.h"

int elligator2(const EVP_PKEY * restrict pkey, uint8_t out_elligator[static restrict COBFS4_ELLIGATOR_LEN]);
EVP_PKEY *elligator2_inv(const uint8_t buffer[static restrict COBFS4_ELLIGATOR_LEN]);

bool elligator_valid(const EVP_PKEY * restrict pkey);

#endif /* COBFS4_ELLIGATOR */
