# cobfs4
An implementation of Obfs4 pluggable transport in C

# DISCLAIMER
I am not a professional cryptographer, and this code has not been audited.
It features deviations from the original Obfs4 spec, and a handwritten Elligator2 implementation.
Use at your own risk, and above all, do not use this in production.

## Known Deviations from Spec
This library makes some opinionated deviations from the original, mainly for simplicity.
It does not attempt to be compatible with existing implementations.
It intentionally does not implement the Tor Pluggable transport APIs to prevent users from attempting to replace existing usages.
The goal of this project is for a simple straightforward way to utilize the obfs4 protocol in C, similar to doing send/recv on a socket.
This project uses OpenSSL for its cryptographic primitives, so some deviations from the spec were made to accomodate availability.

Known changes:
 - ChaCha20 instead of XSalsa20
 - SHA-512/256 instead of SHA-256/128
 - Support for arbitrary shared data lengths instead of a 32-byte public key (Data input is hashed with SHA-512/256)
 - The PRNG seed is always sent as part of the server response
 - Protocol polymorphism is exclusively in "paranoid" mode (packet length and write timing modification)

Additionally, the seeded PRNG used is a hand-written fast key erasure ChaCha20 generator.
See https://blog.cr.yp.to/20170723-random.html for more details on this approach.
The spec doesn't not specify the implementation of the PRNG, nor how it is used beyond the uniform distribution within a certain range.

I believe that none of these changes will affect security meaningfully, but as this code has not been audited, these claims are unsubstantiated.

## Build
CMake is the build system used, and so the standard usage applies:
```
mkdir bin
cd bin
cmake ..
make
sudo make install
```

### Libraries and Version requirements
 - CMake 3.13 or later
 - C99 standard compiler
 - OpenSSL 1.1.1
 - Linux operating system

## Library Usage
The library attempts to maintain a simple API to mimic the standard send/recv calls for C networking applications.
The API is as follows:

```
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
```

Usage of the API involves an initialization call, followed by read/write calls, and then a cleanup when complete.
For stream initialization, an existing connected TCP socket is required.
When used this way for initialization, the ownership of the socket passes to cobfs4.
The user of the library MUST NOT close or modify this socket after this point.

Reads may be blocking or nonblocking, and the COBFS4_AGAIN error code is returned to signal that EAGAIN was received by the library.
The decision whether reads are blocking or not is determined by reading the O_NONBLOCK flag on the socket during initialization.
An application may use existing techniques for handling nonblocking sockets, such as epoll, with the socket passed in during initialization.
Reads are also limited to returning up to COBFS4_MAX_DATA_LEN bytes per read call.
The out_len parameter will contain the actual length of the data read.

Writes are always done in a blocking fashion.
This is done intentionally, since the maximum packet size is designed to fit within an MTU.
Additionally, the protocol polymorphism drastically limits the throughput of the protocol, so a write should never block on the socket.

There are example client and server applications in the examples/ folder, demonstrating usage of the API.

### Thread Safety
The library does not use any concurrency primitives or synchronization.
Nevertheless, it also does not involve any shared global state.
In general, using the struct cobsf4_stream in multiple threads requires synchronization on the part of the caller.
One exception however is that due to a separation of states, reading and writing may occur simultaneously, so long as only one reader and writer is active.
The library is not fork-safe, and a stream cannot be used in multiple processesor.

## Throughput
Due to the "paranoid" nature of use in the protocol polymorphism, throughput is severely limited.
According to the Scramblesuit spec, which is referenced in Obfs4 for the protocol polymorphism, the following ranges are used:

> For the packet length distribution, all values SHOULD be in {21..1448}.
> For the inter-arrival time distribution, all values SHOULD be in the interval [0, 0.01].

This means that ideal throughput is 1448 byte packets sent with zero delay, but that is statistically unlikely, so it will not be considered.
Since we follow the "paranoid" mode of execution, unlike the ScrambleSuit tendency to maximize MTU sized packets, we will fall somewhere in that range.

Assuming median values in both ranges, that equates to a 735 byte packet being sent every 5ms.
This results in a throughput of 147KBps.

A worst case scenario involves a 21 byte packet sent every 10ms.
This results in a throughput of 2.1KBps.

Therefore, the throughput of this library is intentionally very slow to maximize randomness in the packet flow metadata.
This must be taken into consideration when using this library, as it is significantly lower than most end users would expect from a networking library.
