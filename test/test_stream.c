#include <openssl/rand.h>

#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
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
    intptr_t (*test_case)(struct cobfs4_stream *);
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
    setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));

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

    setsockopt(server_socket, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));

    if (cobfs4_server_init(test->stream, server_socket,
                test->server_priv, test->identity,
                sizeof(test->identity), test->timing_seed)) {
        return (void *) -1;
    }

    func_ret = (void *) test->test_case(test->stream);

    return func_ret;
}

static void wait_for_data(int fd) {
    struct epoll_event ev;
    struct epoll_event event;
    int epollfd = epoll_create1(0);

    memset(&ev, 0, sizeof(ev));
    memset(&event, 0, sizeof(event));

    ev.events = EPOLLIN;
    ev.data.fd = fd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);

    epoll_wait(epollfd, &event, 1, -1);
}


intptr_t handshake_test(struct cobfs4_stream *stream) {
    (void)stream;
    return 0;
}

intptr_t stream_test(struct cobfs4_stream *stream) {
    //4k bytes
    const size_t buff_size = 1 << 12;
    uint8_t buffer[buff_size];
    int len = 0;
    size_t total = 0;

    memset(buffer, 'A', sizeof(buffer));

    /*
     * The alternating nature is needed
     * to prevent deadlocks for the test
     */
    if (stream->type == COBFS4_SERVER) {
        do {
            len = cobfs4_read(stream, buffer);
            if (len < 0) {
                return -1;
            }
            if (len == 0) {
                wait_for_data(stream->fd);
                continue;
            }
            total += len;
        } while(total < buff_size);
        if (cobfs4_write(stream, buffer, buff_size)) {
            return -1;
        }
    } else {
        if (cobfs4_write(stream, buffer, buff_size)) {
            return -1;
        }
        do {
            len = cobfs4_read(stream, buffer);
            if (len < 0) {
                return -1;
            }
            if (len == 0) {
                wait_for_data(stream->fd);
                continue;
            }
            total += len;
        } while(total < buff_size);
    }
    return 0;
}

void test_stream(void) {
    int good = 0;
    int bad = 0;
    int i;

    for (i = 0; i < TEST_CASE_COUNT; ++i) {
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
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        server_ctx.server_ntor = client_ctx.server_ntor;

        memcpy(server_ctx.identity, client_ctx.identity, sizeof(client_ctx.identity));
        memcpy(server_ctx.timing_seed, client_ctx.timing_seed, sizeof(client_ctx.timing_seed));

        if (!EVP_PKEY_get_raw_private_key(client_ctx.server_ntor, client_ctx.server_priv, &(size_t){COBFS4_PRIVKEY_LEN})) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (!EVP_PKEY_get_raw_public_key(client_ctx.server_ntor, client_ctx.server_pub, &(size_t){COBFS4_PUBKEY_LEN})) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (!EVP_PKEY_get_raw_private_key(server_ctx.server_ntor, server_ctx.server_priv, &(size_t){COBFS4_PRIVKEY_LEN})) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (!EVP_PKEY_get_raw_public_key(server_ctx.server_ntor, server_ctx.server_pub, &(size_t){COBFS4_PUBKEY_LEN})) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
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

        close(listen_socket);

        sem_destroy(&sem);

        if ((intptr_t)client_ret == -1) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if ((intptr_t)server_ret == -1) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }

        if (memcmp(client_stream.read_key, server_stream.write_key, sizeof(client_stream.read_key)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(server_stream.read_key, client_stream.write_key, sizeof(server_stream.read_key)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(client_stream.read_nonce_prefix, server_stream.write_nonce_prefix, sizeof(client_stream.read_nonce_prefix)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(server_stream.read_nonce_prefix, client_stream.write_nonce_prefix, sizeof(server_stream.read_nonce_prefix)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(&client_stream.read_siphash, &server_stream.write_siphash, sizeof(client_stream.read_siphash)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(&server_stream.read_siphash, &client_stream.write_siphash, sizeof(server_stream.read_siphash)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(&client_stream.rng, &server_stream.rng, sizeof(client_stream.rng)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        ++good;
        EVP_PKEY_free(client_ctx.server_ntor);
        cobfs4_cleanup(&client_stream);
        cobfs4_cleanup(&server_stream);
    }

    printf("Stream handshake testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);

    good = 0;
    bad = 0;

    for (i = 0; i < TEST_CASE_COUNT; ++i) {
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
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        server_ctx.server_ntor = client_ctx.server_ntor;

        memcpy(server_ctx.identity, client_ctx.identity, sizeof(client_ctx.identity));
        memcpy(server_ctx.timing_seed, client_ctx.timing_seed, sizeof(client_ctx.timing_seed));

        if (!EVP_PKEY_get_raw_private_key(client_ctx.server_ntor, client_ctx.server_priv, &(size_t){COBFS4_PRIVKEY_LEN})) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (!EVP_PKEY_get_raw_public_key(client_ctx.server_ntor, client_ctx.server_pub, &(size_t){COBFS4_PUBKEY_LEN})) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (!EVP_PKEY_get_raw_private_key(server_ctx.server_ntor, server_ctx.server_priv, &(size_t){COBFS4_PRIVKEY_LEN})) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (!EVP_PKEY_get_raw_public_key(server_ctx.server_ntor, server_ctx.server_pub, &(size_t){COBFS4_PUBKEY_LEN})) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }

        client_ctx.test_case = stream_test;
        server_ctx.test_case = stream_test;

        client_ctx.stream = &client_stream;
        server_ctx.stream = &server_stream;

        sem_init(&sem, 0, 0);

        pthread_create(&server_thread, NULL, server_thread_routine, &server_ctx);

        pthread_create(&client_thread, NULL, client_thread_routine, &client_ctx);

        pthread_join(client_thread, &client_ret);
        pthread_join(server_thread, &server_ret);

        close(listen_socket);

        sem_destroy(&sem);

        if ((intptr_t)client_ret == -1) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if ((intptr_t)server_ret == -1) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }

        if (memcmp(client_stream.read_key, server_stream.write_key, sizeof(client_stream.read_key)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(server_stream.read_key, client_stream.write_key, sizeof(server_stream.read_key)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(client_stream.read_nonce_prefix, server_stream.write_nonce_prefix, sizeof(client_stream.read_nonce_prefix)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(server_stream.read_nonce_prefix, client_stream.write_nonce_prefix, sizeof(server_stream.read_nonce_prefix)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(&client_stream.read_siphash, &server_stream.write_siphash, sizeof(client_stream.read_siphash)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(&server_stream.read_siphash, &client_stream.write_siphash, sizeof(server_stream.read_siphash)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        if (memcmp(&client_stream.rng, &server_stream.rng, sizeof(client_stream.rng)) != 0) {
            ++bad;
            EVP_PKEY_free(client_ctx.server_ntor);
            cobfs4_cleanup(&client_stream);
            cobfs4_cleanup(&server_stream);
            continue;
        }
        EVP_PKEY_free(client_ctx.server_ntor);
        cobfs4_cleanup(&client_stream);
        cobfs4_cleanup(&server_stream);

        ++good;
    }

    printf("Stream data exchange testing ran %d times\nResults:\nGood: %d\nBad: %d\n", i, good, bad);
}
