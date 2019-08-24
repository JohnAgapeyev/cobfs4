#ifndef COBFS4_KDF
#define COBFS4_KDF

int hkdf(const unsigned char * restrict mesg,
        size_t mesg_len,
        const unsigned char * restrict salt,
        size_t salt_len,
        const unsigned char *restrict key,
        size_t key_len,
        unsigned char * restrict out_data,
        size_t out_len);

#endif
