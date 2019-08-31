#include "cobfs4.h"
#include "test.h"

int main(void) {
    test_elligator();
    test_hmac();
    test_ecdh();
    return 0;
}
