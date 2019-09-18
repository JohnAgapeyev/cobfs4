#ifndef COBFS4_KDF
#define COBFS4_KDF

int hkdf(const uint8_t * restrict mesg,
        size_t mesg_len,
        const uint8_t * restrict salt,
        size_t salt_len,
        const uint8_t *restrict key,
        size_t key_len,
        uint8_t * restrict out_data,
        size_t out_len);

#endif
