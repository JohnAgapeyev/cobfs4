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
static const char *server_string = "Server";

int server_ntor(EVP_PKEY * restrict ephem_keypair,
        EVP_PKEY * restrict remote_pubkey,
        const struct shared_data * restrict shared,
        struct ntor_output * restrict out) {

    /*
     * Numbers are as follows:
     * 2 ecdh results
     * node id digest
     * 3 public keys
     * and the protoid string
     * Plus a null byte
     */
    uint8_t secret_input[(2 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN + (3 * COBFS4_PUBKEY_LEN)
        + strlen(protoid) + 1];
    uint8_t verify[COBFS4_HMAC_LEN];
    /*
     * Numbers are as follows:
     * 1 HMAC
     * node id digest
     * 3 public keys
     * the protoid string
     * the "Server" string
     * Plus a null byte
     */
    uint8_t auth_input[COBFS4_HMAC_LEN + COBFS4_HASH_LEN + (3 * COBFS4_PUBKEY_LEN)
        + strlen(protoid) + strlen(server_string) + 1];

    size_t tmp_len;

    if (ecdh_derive(ephem_keypair, remote_pubkey, secret_input)) {
        goto error;
    }
    if (ecdh_derive(shared->ntor, remote_pubkey, secret_input + COBFS4_PUBKEY_LEN)) {
        goto error;
    }

    memcpy(secret_input + (2 * COBFS4_PUBKEY_LEN), shared->identity_digest, COBFS4_HASH_LEN);

    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(shared->ntor, secret_input + (2 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN, &tmp_len)) {
        goto error;
    }
    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(remote_pubkey, secret_input + (3 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN, &tmp_len)) {
        goto error;
    }
    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(ephem_keypair, secret_input + (4 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN, &tmp_len)) {
        goto error;
    }

    memcpy(secret_input + (5 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN, protoid, strlen(protoid));

    const size_t secret_len = (5 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN + strlen(protoid);

    if (hmac_gen((const uint8_t *) t_key, strlen(t_key), secret_input, secret_len, out->key_seed)) {
        goto error;
    }

    if (hmac_gen((const uint8_t *) t_verify, strlen(t_verify), secret_input, secret_len, verify)) {
        goto error;
    }

    memcpy(auth_input, verify, COBFS4_HMAC_LEN);
    memcpy(auth_input + COBFS4_HMAC_LEN, shared->identity_digest, COBFS4_HASH_LEN);
    memcpy(auth_input + COBFS4_HMAC_LEN + COBFS4_HASH_LEN,
            secret_input + (2 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN, COBFS4_PUBKEY_LEN);
    memcpy(auth_input + COBFS4_HMAC_LEN + COBFS4_HASH_LEN + COBFS4_PUBKEY_LEN,
            secret_input + (4 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN,
            COBFS4_PUBKEY_LEN);
    memcpy(auth_input + COBFS4_HMAC_LEN + COBFS4_HASH_LEN + (2 * COBFS4_PUBKEY_LEN),
            secret_input + (3 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN,
            COBFS4_PUBKEY_LEN);
    memcpy(auth_input + COBFS4_HMAC_LEN + COBFS4_HASH_LEN + (3 * COBFS4_PUBKEY_LEN),
            protoid, strlen(protoid));
    memcpy(auth_input + COBFS4_HMAC_LEN + COBFS4_HASH_LEN + (3 * COBFS4_PUBKEY_LEN) + strlen(protoid),
            server_string, strlen(server_string));

    size_t auth_len = COBFS4_HMAC_LEN + COBFS4_HASH_LEN + (3 * COBFS4_PUBKEY_LEN)
        + strlen(protoid) + strlen(server_string);

    if (hmac_gen((const uint8_t *) t_mac, strlen(t_mac), auth_input, auth_len, out->auth_tag)) {
        goto error;
    }

    return 0;

error:
    OPENSSL_cleanse(out->auth_tag, COBFS4_AUTH_LEN);
    OPENSSL_cleanse(out->key_seed, COBFS4_SEED_LEN);
    return -1;
}

int client_ntor(EVP_PKEY * restrict ephem_keypair,
        EVP_PKEY * restrict remote_pubkey,
        const struct shared_data * restrict shared,
        struct ntor_output * restrict out) {
    /*
     * Numbers are as follows:
     * 2 ecdh results
     * node id digest
     * 3 public keys
     * and the protoid string
     * Plus a null byte
     */
    uint8_t secret_input[(2 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN + (3 * COBFS4_PUBKEY_LEN)
        + strlen(protoid) + 1];
    uint8_t verify[COBFS4_HMAC_LEN];
    /*
     * Numbers are as follows:
     * 1 HMAC
     * node id digest
     * 3 public keys
     * the protoid string
     * the "Server" string
     * Plus a null byte
     */
    uint8_t auth_input[COBFS4_HMAC_LEN + COBFS4_HASH_LEN + (3 * COBFS4_PUBKEY_LEN)
        + strlen(protoid) + strlen(server_string) + 1];

    size_t tmp_len;

    if (ecdh_derive(ephem_keypair, remote_pubkey, secret_input)) {
        goto error;
    }
    if (ecdh_derive(ephem_keypair, shared->ntor, secret_input + COBFS4_PUBKEY_LEN)) {
        goto error;
    }

    memcpy(secret_input + (2 * COBFS4_PUBKEY_LEN), shared->identity_digest, COBFS4_HASH_LEN);

    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(shared->ntor, secret_input + (2 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN, &tmp_len)) {
        goto error;
    }
    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(ephem_keypair, secret_input + (3 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN, &tmp_len)) {
        goto error;
    }
    tmp_len = 32;
    if (!EVP_PKEY_get_raw_public_key(remote_pubkey, secret_input + (4 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN, &tmp_len)) {
        goto error;
    }
    memcpy(secret_input + (5 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN, protoid, strlen(protoid));

    const size_t secret_len = (5 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN + strlen(protoid);

    if (hmac_gen((const uint8_t *) t_key, strlen(t_key), secret_input, secret_len, out->key_seed)) {
        goto error;
    }

    if (hmac_gen((const uint8_t *) t_verify, strlen(t_verify), secret_input, secret_len, verify)) {
        goto error;
    }

    memcpy(auth_input, verify, COBFS4_HMAC_LEN);
    memcpy(auth_input + COBFS4_HMAC_LEN, shared->identity_digest, COBFS4_HASH_LEN);
    memcpy(auth_input + COBFS4_HMAC_LEN + COBFS4_HASH_LEN,
            secret_input + (2 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN, COBFS4_PUBKEY_LEN);
    memcpy(auth_input + COBFS4_HMAC_LEN + COBFS4_HASH_LEN + COBFS4_PUBKEY_LEN,
            secret_input + (4 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN,
            COBFS4_PUBKEY_LEN);
    memcpy(auth_input + COBFS4_HMAC_LEN + COBFS4_HASH_LEN + (2 * COBFS4_PUBKEY_LEN),
            secret_input + (3 * COBFS4_PUBKEY_LEN) + COBFS4_HASH_LEN,
            COBFS4_PUBKEY_LEN);
    memcpy(auth_input + COBFS4_HMAC_LEN + COBFS4_HASH_LEN + (3 * COBFS4_PUBKEY_LEN),
            protoid, strlen(protoid));
    memcpy(auth_input + COBFS4_HMAC_LEN + COBFS4_HASH_LEN + (3 * COBFS4_PUBKEY_LEN) + strlen(protoid),
            server_string, strlen(server_string));

    size_t auth_len = COBFS4_HMAC_LEN + COBFS4_HASH_LEN + (3 * COBFS4_PUBKEY_LEN)
        + strlen(protoid) + strlen(server_string);

    if (hmac_gen((const uint8_t *) t_mac, strlen(t_mac), auth_input, auth_len, out->auth_tag)) {
        goto error;
    }

    return 0;

error:
    OPENSSL_cleanse(out->auth_tag, COBFS4_AUTH_LEN);
    OPENSSL_cleanse(out->key_seed, COBFS4_SEED_LEN);
    return -1;
}
