#include <string.h>
#include <openssl/evp.h>

#include "ecdh.h"
#include "kdf.h"
#include "hash.h"
#include "hmac.h"
#include "ntor.h"

static const char *protoid = "ntor-curve25519-sha256-1";
static const char *t_mac = "ntor-curve25519-sha256-1:mac";
static const char *t_key = "ntor-curve25519-sha256-1:key_extract";
static const char *t_verify = "ntor-curve25519-sha256-1:verify";

int server_ntor(EVP_PKEY *ephem_keypair,
        EVP_PKEY *ntor_keypair,
        EVP_PKEY *remote_pubkey,
        const unsigned char identity_digest[static const 32],
        unsigned char out_auth[static const 32]) {

    /*
     * Numbers are as follows:
     * 2 ecdh results
     * node id digest
     * 3 public keys
     * and the protoid string
     */
    unsigned char secret_input[32 + 32 + 32 + 32 + 32 + 32 + strlen(protoid)];
    unsigned char key_seed[16];
    unsigned char verify[16];
    unsigned char auth_input[16 + (32 * 4) + strlen(protoid) + 6];

    size_t tmp_len;

    if (ecdh_derive(ephem_keypair, remote_pubkey, secret_input)) {
        return -1;
    }
    if (ecdh_derive(ntor_keypair, remote_pubkey, secret_input + 32)) {
        return -1;
    }

    memcpy(secret_input + 64, identity_digest, 32);

    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(ntor_keypair, secret_input + 96, &tmp_len)) {
        return -1;
    }
    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(remote_pubkey, secret_input + 128, &tmp_len)) {
        return -1;
    }
    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(ephem_keypair, secret_input + 160, &tmp_len)) {
        return -1;
    }

    memcpy(secret_input + 192, protoid, strlen(protoid));

    if (hmac_gen((const unsigned char *) t_key, strlen(t_key), secret_input, sizeof(secret_input), key_seed)) {
        return -1;
    }

    if (hmac_gen((const unsigned char *) t_verify, strlen(t_verify), secret_input, sizeof(secret_input), verify)) {
        return -1;
    }

    memcpy(auth_input, verify, 16);
    memcpy(auth_input + 16, identity_digest, 32);
    memcpy(auth_input + 48, secret_input + 96, 32);
    memcpy(auth_input + 80, secret_input + 160, 32);
    memcpy(auth_input + 112, secret_input + 128, 32);
    memcpy(auth_input + 144, protoid, strlen(protoid));
    memcpy(auth_input + 144 + strlen(protoid), "Server", 6);

    if (hmac_gen((const unsigned char *) t_mac, strlen(t_mac), auth_input, sizeof(secret_input), out_auth)) {
        OPENSSL_cleanse(out_auth, 32);
        return -1;
    }

    return 0;
}

int client_ntor(EVP_PKEY *ephem_keypair,
        EVP_PKEY *remote_pubkey,
        EVP_PKEY *preshared_pubkey,
        const unsigned char identity_digest[static const 32],
        unsigned char out_auth[static const 32]) {
    /*
     * Numbers are as follows:
     * 2 ecdh results
     * node id digest
     * 3 public keys
     * and the protoid string
     */
    unsigned char secret_input[32 + 32 + 32 + 32 + 32 + 32 + strlen(protoid)];
    unsigned char key_seed[16];
    unsigned char verify[16];
    unsigned char auth_input[16 + (32 * 4) + strlen(protoid) + 6];

    size_t tmp_len;

    if (ecdh_derive(ephem_keypair, remote_pubkey, secret_input)) {
        return -1;
    }
    if (ecdh_derive(ephem_keypair, preshared_pubkey, secret_input + 32)) {
        return -1;
    }

    memcpy(secret_input + 64, identity_digest, 32);

    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(preshared_pubkey, secret_input + 96, &tmp_len)) {
        return -1;
    }
    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(ephem_keypair, secret_input + 128, &tmp_len)) {
        return -1;
    }
    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(remote_pubkey, secret_input + 160, &tmp_len)) {
        return -1;
    }

    memcpy(secret_input + 192, protoid, strlen(protoid));

    if (hmac_gen((const unsigned char *) t_key, strlen(t_key), secret_input, sizeof(secret_input), key_seed)) {
        return -1;
    }

    if (hmac_gen((const unsigned char *) t_verify, strlen(t_verify), secret_input, sizeof(secret_input), verify)) {
        return -1;
    }

    memcpy(auth_input, verify, 16);
    memcpy(auth_input + 16, identity_digest, 32);
    memcpy(auth_input + 48, secret_input + 96, 32);
    memcpy(auth_input + 80, secret_input + 160, 32);
    memcpy(auth_input + 112, secret_input + 128, 32);
    memcpy(auth_input + 144, protoid, strlen(protoid));
    memcpy(auth_input + 144 + strlen(protoid), "Server", 6);

    if (hmac_gen((const unsigned char *) t_mac, strlen(t_mac), auth_input, sizeof(secret_input), out_auth)) {
        OPENSSL_cleanse(out_auth, 32);
        return -1;
    }

    return 0;
}
