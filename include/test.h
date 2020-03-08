#ifndef COBFS4_TEST_HEADER
#define COBFS4_TEST_HEADER

#define TEST_CASE_COUNT 10

void test_elligator(void);
void test_hmac(void);
void test_ecdh(void);
void test_ntor(void);
void test_handshake(void);
void test_aead(void);
void test_frame(void);
void test_seeded_random(void);
void test_siphash(void);
void test_stream(void);

#endif /* COBFS4_TEST_HEADER */
