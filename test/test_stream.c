#include <openssl/rand.h>

#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <semaphore.h>

#include "cobfs4.h"
#include "test.h"
#include "stream.h"
#include "constants.h"
#include "ecdh.h"
#include "utils.h"

struct stream_test_ctx {
    uint8_t server_priv[COBFS4_PRIVKEY_LEN];
    uint8_t server_pub[COBFS4_PUBKEY_LEN];
    uint8_t identity[1234];
    uint8_t timing_seed[COBFS4_SERVER_TIMING_SEED_LEN];
    EVP_PKEY *server_ntor;
    struct cobfs4_stream *stream;
    uintptr_t (*test_case)(struct cobfs4_stream *);
};

static sem_t sem;
static int server_socket;
static int listen_socket;
static int client_socket;

void *client_thread_routine(void *ctx) {
    struct stream_test_ctx *test = ctx;
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    void * func_ret;

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    servaddr.sin_port = htons(12345);

    setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    sem_wait(&sem);

    connect(client_socket, (struct sockaddr *)&servaddr, sizeof(servaddr));

    sem_post(&sem);


    if (cobfs4_client_init(test->stream, client_socket,
                test->server_pub, test->identity,
                sizeof(test->identity))) {
        return (void *)-1;
    }

    func_ret = (void *) test->test_case(test->stream);

    return func_ret;
}

void *server_thread_routine(void *ctx) {
    struct stream_test_ctx *test = ctx;
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    void * func_ret;

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(12345);

    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    bind(listen_socket, (struct sockaddr *)&servaddr, sizeof(servaddr));
    listen(listen_socket, 5);

    sem_post(&sem);

    server_socket = accept(listen_socket, NULL, NULL);

    if (cobfs4_server_init(test->stream, server_socket,
                test->server_priv, test->identity,
                sizeof(test->identity), test->timing_seed)) {
        return (void *) -1;
    }

    func_ret = (void *) test->test_case(test->stream);

    return func_ret;
}

uintptr_t handshake_test(struct cobfs4_stream *stream) {
    (void)stream;
    return 0;
}

void test_stream(void) {
    int good = 0;
    int bad = 0;
    int i;

    for (i = 0; i < 10000; ++i) {
        struct stream_test_ctx client_ctx;
        struct stream_test_ctx server_ctx;

        pthread_t client_thread;
        pthread_t server_thread;

        struct cobfs4_stream client_stream;
        struct cobfs4_stream server_stream;

        void *client_ret;
        void *server_ret;

        RAND_bytes((unsigned char *) &client_ctx.identity, sizeof(client_ctx.identity));
        RAND_bytes((unsigned char *) &client_ctx.timing_seed, sizeof(client_ctx.timing_seed));

        client_ctx.server_ntor = ecdh_key_alloc();
        if (client_ctx.server_ntor == NULL) {
            ++bad;
            continue;
        }
        server_ctx.server_ntor = client_ctx.server_ntor;

        memcpy(server_ctx.identity, client_ctx.identity, sizeof(client_ctx.identity));
        memcpy(server_ctx.timing_seed, client_ctx.timing_seed, sizeof(client_ctx.timing_seed));

        if (!EVP_PKEY_get_raw_private_key(client_ctx.server_ntor, client_ctx.server_priv, &(size_t){COBFS4_PRIVKEY_LEN})) {
            ++bad;
            continue;
        }
        if (!EVP_PKEY_get_raw_public_key(client_ctx.server_ntor, client_ctx.server_pub, &(size_t){COBFS4_PUBKEY_LEN})) {
            ++bad;
            continue;
        }
        if (!EVP_PKEY_get_raw_private_key(server_ctx.server_ntor, server_ctx.server_priv, &(size_t){COBFS4_PRIVKEY_LEN})) {
            ++bad;
            continue;
        }
        if (!EVP_PKEY_get_raw_public_key(server_ctx.server_ntor, server_ctx.server_pub, &(size_t){COBFS4_PUBKEY_LEN})) {
            ++bad;
            continue;
        }

        client_ctx.test_case = handshake_test;
        server_ctx.test_case = handshake_test;

        client_ctx.stream = &client_stream;
        server_ctx.stream = &server_stream;

        sem_init(&sem, 0, 0);

        pthread_create(&server_thread, NULL, server_thread_routine, &server_ctx);

        pthread_create(&client_thread, NULL, client_thread_routine, &client_ctx);

        pthread_join(client_thread, &client_ret);
        pthread_join(server_thread, &server_ret);

        close(client_socket);
        close(server_socket);
        close(listen_socket);

        sem_destroy(&sem);

        if ((intptr_t)client_ret == -1) {
            ++bad;
            continue;
        }
        if ((intptr_t)server_ret == -1) {
            ++bad;
            continue;
        }

        if (memcmp(client_stream.read_key, server_stream.write_key, sizeof(client_stream.read_key)) != 0) {
            ++bad;
            continue;
        }
        if (memcmp(server_stream.read_key, client_stream.write_key, sizeof(server_stream.read_key)) != 0) {
            ++bad;
            continue;
        }
        if (memcmp(client_stream.read_nonce_prefix, server_stream.write_nonce_prefix, sizeof(client_stream.read_nonce_prefix)) != 0) {
            ++bad;
            continue;
        }
        if (memcmp(server_stream.read_nonce_prefix, client_stream.write_nonce_prefix, sizeof(server_stream.read_nonce_prefix)) != 0) {
            ++bad;
            continue;
        }
        if (memcmp(&client_stream.read_siphash, &server_stream.write_siphash, sizeof(client_stream.read_siphash)) != 0) {
            ++bad;
            continue;
        }
        if (memcmp(&server_stream.read_siphash, &client_stream.write_siphash, sizeof(server_stream.read_siphash)) != 0) {
            ++bad;
            continue;
        }
        if (memcmp(&client_stream.rng, &server_stream.rng, sizeof(client_stream.rng)) != 0) {
            ++bad;
            continue;
        }
        ++good;
    }

    printf("Stream handshake testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
