#ifndef COBFS4_HMAC
#define COBFS4_HMAC

/*
 * hmac must be at least 16 bytes
 */
int hmac_gen(const unsigned char *key, const size_t key_len,
        const unsigned char *message, const size_t mesg_len,
        unsigned char *hmac);

int hmac_verify(const unsigned char *key, const size_t key_len,
        const unsigned char *message, const size_t mesg_len,
        const unsigned char *hmac);

#endif /* COBFS4_HMAC */
