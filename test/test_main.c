#include "cobfs4.h"
#include "test.h"

int main(void) {
#if 0
    test_elligator();
    test_hmac();
    test_ecdh();
    test_ntor();
    test_handshake();
    test_aead();
    test_frame();
    test_seeded_random();
    test_siphash();
#else
    test_stream();
#endif
    return 0;
}
