#ifndef COBFS4_ELLIGATOR
#define COBFS4_ELLIGATOR

#include <stdbool.h>
#include <openssl/evp.h>

#include "constants.h"

enum cobfs4_return_code elligator2_inv(const EVP_PKEY * restrict pkey, uint8_t out_elligator[static restrict COBFS4_ELLIGATOR_LEN]);
EVP_PKEY *elligator2(const uint8_t buffer[static restrict COBFS4_ELLIGATOR_LEN]);

bool elligator_valid(const EVP_PKEY * restrict pkey);

#endif /* COBFS4_ELLIGATOR */
