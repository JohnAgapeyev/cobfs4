#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "packet.h"
#include "elligator.h"
#include "hmac.h"

int create_client_request(const EVP_PKEY *self_keypair,
        const uint8_t * const shared_knowledge,
        const size_t shared_len,
        struct client_request *out_req) {
    int res;

    res = elligator2(self_keypair, out_req->elligator);
    if (res) {
        goto error;
    }

    return 0;

error:
    OPENSSL_cleanse(out_req, sizeof(*out_req));
    return -1;
}

