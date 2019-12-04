#include "cobfs4.h"
#include "test.h"

int main(void) {
    test_elligator();
    test_hmac();
    test_ecdh();
    test_ntor();
    test_handshake();
    test_aead();
    test_seeded_random();
    return 0;
}
