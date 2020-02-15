#ifndef COBFS4_HMAC
#define COBFS4_HMAC

#include "constants.h"

enum cobfs4_return_code hmac_gen(const uint8_t * restrict key, const size_t key_len,
        const uint8_t * restrict message, const size_t mesg_len,
        uint8_t hmac[static restrict COBFS4_HMAC_LEN]);

enum cobfs4_return_code hmac_verify(const uint8_t * restrict key, const size_t key_len,
        const uint8_t * restrict message, const size_t mesg_len,
        const uint8_t hmac[static restrict COBFS4_HMAC_LEN]);

#endif /* COBFS4_HMAC */
