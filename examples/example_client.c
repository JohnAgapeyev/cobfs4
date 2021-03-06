#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "cobfs4.h"

char *shared_data = "cobfs4 example shared data";

/*
 * Yes yes yes I know this is awful.
 * This is an example for the purposes of library usage.
 * For real world applications, the server public key would be
 * shared via Out-Of-Band methods.
 *
 * For simplicity, we use a hardcoded private key shared between
 * client and server to ensure a consistent public key between the
 * two example pieces of code.
 *
 * The client never uses this private key except to generate
 * the corresponding public key.
 *
 * The server public key has a requirement of being valid for elligator,
 * so a valid one was generated that fit that requirement.
 * The actual key contents are not sensitive and are arbitrary.
 */
const char server_privkey[] = {
    0x98, 0xf7, 0xf4, 0x07, 0x12, 0xbd, 0xc6, 0x35, 0x5a, 0x95, 0xd6, 0x5d, 0x82, 0x87, 0x3a, 0x5a,
    0xdf, 0xc2, 0xb9, 0x37, 0xd8, 0xbe, 0x00, 0x26, 0x7b, 0xf4, 0xe3, 0xfe, 0x33, 0x7b, 0x82, 0x53
};

void *file_read(void *data) {
    struct cobfs4_stream *stream = data;
    ssize_t size;
    unsigned char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    for (;;) {
        size = read(STDIN_FILENO, buffer, sizeof(buffer));
        if (size == -1) {
            break;
        } else if (size == 0) {
            break;
        }

        if (cobfs4_write(stream, buffer, size) != COBFS4_OK) {
            break;
        }
    }
    return NULL;
}

void *network_read(void *data) {
    struct cobfs4_stream *stream = data;
    enum cobfs4_return_code rc;
    size_t len;
    unsigned char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    for (;;) {
        rc = cobfs4_read(stream, buffer, &len);
        if (rc == COBFS4_ERROR) {
            break;
        }
        if (rc == COBFS4_AGAIN) {
            continue;
        }
        write(STDOUT_FILENO, buffer, len);
        fsync(STDOUT_FILENO);
    }
    return NULL;
}

int main(int argc, char **argv) {
    struct cobfs4_stream *stream = malloc(cobfs4_stream_size());
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);

    EVP_PKEY *server_keypair = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, server_privkey, COBFS4_PRIVKEY_LEN);

    unsigned char pubkey[COBFS4_PUBKEY_LEN];
    EVP_PKEY_get_raw_public_key(server_keypair, pubkey, &(size_t){COBFS4_PUBKEY_LEN});

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    servaddr.sin_port = htons(12345);

    setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    connect(client_socket, (struct sockaddr *)&servaddr, sizeof(servaddr));

    if (cobfs4_client_init(stream, client_socket,
                pubkey, shared_data,
                strlen(shared_data)) != COBFS4_OK) {
        close(client_socket);
        EVP_PKEY_free(server_keypair);
        return EXIT_FAILURE;
    }

    pthread_t file_thread;
    pthread_t network_thread;

    pthread_create(&file_thread, NULL, file_read, stream);
    pthread_create(&network_thread, NULL, network_read, stream);

    pthread_join(file_thread, NULL);
    pthread_join(network_thread, NULL);

    cobfs4_cleanup(stream);
    EVP_PKEY_free(server_keypair);

    free(stream);

    return EXIT_SUCCESS;
}
