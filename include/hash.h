#ifndef COBFS4_HASH
#define COBFS4_HASH

#include "constants.h"

enum cobfs4_return_code hash_data(uint8_t * restrict mesg, size_t mesg_len, uint8_t out_buf[static restrict COBFS4_HASH_LEN]);

#endif
