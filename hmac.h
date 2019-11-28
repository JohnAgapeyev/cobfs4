#ifndef COBFS4_HMAC
#define COBFS4_HMAC

#include "constants.h"

int hmac_gen(const uint8_t * restrict key, const size_t key_len,
        const uint8_t * restrict message, const size_t mesg_len,
        uint8_t hmac[static restrict COBFS4_HMAC_LEN]);

int hmac_verify(const uint8_t * restrict key, const size_t key_len,
        const uint8_t * restrict message, const size_t mesg_len,
        const uint8_t hmac[static restrict COBFS4_HMAC_LEN]);

#endif /* COBFS4_HMAC */
