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
    0x98,
    0xf7,
    0xf4,
    0x07,
    0x12,
    0xbd,
    0xc6,
    0x35,
    0x5a,
    0x95,
    0xd6,
    0x5d,
    0x82,
    0x87,
    0x3a,
    0x5a,
    0xdf,
    0xc2,
    0xb9,
    0x37,
    0xd8,
    0xbe,
    0x00,
    0x26,
    0x7b,
    0xf4,
    0xe3,
    0xfe,
    0x33,
    0x7b,
    0x82,
    0x53
};

int main(int argc, char **argv) {
    size_t len;
    enum cobfs4_return_code rc;
    struct cobfs4_stream stream = {0};
    int listen_socket = socket(AF_INET, SOCK_STREAM, 0);

    unsigned char timing_seed[32];
    memset(timing_seed, 0, sizeof(timing_seed));

    unsigned char buffer[COBFS4_MAX_DATA_LEN];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(12345);

    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    bind(listen_socket, (struct sockaddr *)&servaddr, sizeof(servaddr));
    listen(listen_socket, 5);

    int server_socket = accept(listen_socket, NULL, NULL);

    if (cobfs4_server_init(&stream, server_socket,
                server_privkey, shared_data,
                strlen(shared_data), timing_seed) != COBFS4_OK) {
        goto error;
    }

    if (cobfs4_write(&stream, buffer, sizeof(buffer)) != COBFS4_OK) {
        goto error;
    }

    rc = cobfs4_read(&stream, buffer, &len);
    if (rc == COBFS4_ERROR) {
        goto error;
    }

    cobfs4_cleanup(&stream);
    close(listen_socket);

    return EXIT_SUCCESS;

error:
    cobfs4_cleanup(&stream);
    close(listen_socket);
    return EXIT_FAILURE;
}
