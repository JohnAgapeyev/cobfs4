#ifndef COBFS4_MAIN_HEADER
#define COBFS4_MAIN_HEADER

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define COBFS4_PUBKEY_LEN (32)
#define COBFS4_PRIVKEY_LEN (32)
#define COBFS4_MAX_DATA_LEN (1427)

enum cobfs4_return_code {
    COBFS4_ERROR = -1,
    COBFS4_AGAIN = 0,
    COBFS4_OK = 1,
};

struct cobfs4_stream;

size_t cobfs4_stream_size(void);

enum cobfs4_return_code cobfs4_server_init(struct cobfs4_stream * restrict stream, int socket,
        const uint8_t private_key[static restrict COBFS4_PRIVKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len,
        uint8_t * restrict timing_seed, size_t timing_seed_len);

enum cobfs4_return_code cobfs4_client_init(struct cobfs4_stream * restrict stream, int socket,
        const uint8_t server_pubkey[static restrict COBFS4_PUBKEY_LEN],
        uint8_t * restrict identity_data, size_t identity_len);

enum cobfs4_return_code cobfs4_read(struct cobfs4_stream * restrict stream,
        uint8_t buffer[static restrict COBFS4_MAX_DATA_LEN],
        size_t * restrict out_len);
enum cobfs4_return_code cobfs4_write(struct cobfs4_stream * restrict stream, uint8_t * restrict buffer, size_t buf_len);

void cobfs4_cleanup(struct cobfs4_stream *stream);


#if defined(__cplusplus)
}
#endif

#endif /* COBFS4_MAIN_HEADER */
