#ifndef COBFS4_HMAC
#define COBFS4_HMAC

/*
 * hmac must be at least 16 bytes
 */
int hmac_gen(const uint8_t *key, const size_t key_len,
        const uint8_t *message, const size_t mesg_len,
        uint8_t *hmac);

int hmac_verify(const uint8_t *key, const size_t key_len,
        const uint8_t *message, const size_t mesg_len,
        const uint8_t *hmac);

#endif /* COBFS4_HMAC */
