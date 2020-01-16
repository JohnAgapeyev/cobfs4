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

void *client_thread_routine(void *ctx) {
    struct stream_test_ctx *test = ctx;
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    int ret;
    void * func_ret;

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    servaddr.sin_port = htons(12345);

    setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    sem_wait(&sem);

    ret = connect(client_socket, (struct sockaddr *)&servaddr, sizeof(servaddr));
    //printf("1 %d %d\n", ret, errno);

    sem_post(&sem);


#if 1
    if (cobfs4_client_init(test->stream, client_socket, test->server_pub, test->identity, sizeof(test->identity)) <= 0) {
        printf("Badness\n");
        close(client_socket);
        return (void *)-1;
    }
#else
    uint8_t buf[64];
    ret = send(client_socket, "foobar\0", 7, 0);
    printf("2 %d\n", ret);
    ret = recv(client_socket, buf, 64, 0);
    printf("3 %d\n", ret);
    printf("%s\n", buf);
#endif

    func_ret = (void *) test->test_case(test->stream);

    close(client_socket);

    return func_ret;
}

void *server_thread_routine(void *ctx) {
    struct stream_test_ctx *test = ctx;
    int listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    int ret;
    void * func_ret;

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(12345);

    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    ret = bind(listen_socket, (struct sockaddr *)&servaddr, sizeof(servaddr));
    //printf("4 %d\n", ret);
    ret = listen(listen_socket, 5);
    //printf("5 %d\n", ret);

    sem_post(&sem);

    int server_socket = accept(listen_socket, NULL, NULL);
    //printf("8 %d\n", server_socket);

#if 1
    if (cobfs4_server_init(test->stream, server_socket, test->server_priv, test->identity, sizeof(test->identity), test->timing_seed) <= 0) {
        printf("Server Badness\n");
        close(server_socket);
        close(listen_socket);
        return (void *) -1;
    }
#else
    uint8_t buf[64];
    ret = recv(server_socket, buf, 64, 0);
    printf("6 %d\n", ret);
    ret = send(server_socket, "fizzbuzz\0", 9, 0);
    printf("7 %d\n", ret);
    printf("%s\n", buf);
#endif

    func_ret = (void *) test->test_case(test->stream);

    close(server_socket);
    close(listen_socket);

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

        RAND_bytes((unsigned char *) &client_ctx.identity, sizeof(client_ctx.identity));
        RAND_bytes((unsigned char *) &client_ctx.timing_seed, sizeof(client_ctx.timing_seed));

        client_ctx.server_ntor = ecdh_key_alloc();
        if (client_ctx.server_ntor == NULL) {
            ++bad;
            continue;
        }
        server_ctx.server_ntor = client_ctx.server_ntor;

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

        pthread_join(client_thread, NULL);
        pthread_join(server_thread, NULL);

        sem_destroy(&sem);

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
