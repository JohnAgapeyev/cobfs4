#include <stdio.h>

#include "cobfs4.h"
#include "test.h"

#define OPTPARSE_IMPLEMENTATION
#define OPTPARSE_API static

#include "optparse.h"

void help()
{
    puts("cobfs4_test ([option])\n"
         "  --elligator, -e\n"
         "  --hmac, -h\n"
         "  --ecdh, -d\n"
         "  --ntor, -n\n"
         "  --hanshake, -s\n"
         "  --aead, -a\n"
         "  --frame, -f\n"
         "  --siphash, -i\n"
         "  --stream, -m\n"
         "  --help, -p\n"
         "All tests are executed when started without any argument."
        );
}

int main(int argc, char **argv) {
    int option;
    struct optparse options;
    struct optparse_long long_options[] = {
        {"elligator", 'e', OPTPARSE_NONE},
        {"hmac", 'h', OPTPARSE_NONE},
        {"ecdh", 'd', OPTPARSE_NONE},
        {"ntor", 'n', OPTPARSE_NONE},
        {"handshake", 's', OPTPARSE_NONE},
        {"aead", 'a', OPTPARSE_NONE},
        {"frame", 'f', OPTPARSE_NONE},
        {"random", 'r', OPTPARSE_NONE},
        {"siphash", 'i', OPTPARSE_NONE},
        {"stream", 'm', OPTPARSE_NONE},
        {"help", 'p', OPTPARSE_NONE},
        {0}
    };

    if (argc == 1) {
        test_elligator();
        test_hmac();
        test_ecdh();
        test_ntor();
        test_handshake();
        test_aead();
        test_frame();
        test_seeded_random();
        test_siphash();
        test_stream();
        return 0;
    }

    optparse_init(&options, argv);
    while ((option = optparse_long(&options, long_options, NULL)) != -1) {
        switch (option) {
        case 'e':
            test_elligator();
            break;
        case 'h':
            test_hmac();
            break;
        case 'd':
            test_ecdh();
            break;
        case 'n':
            test_ntor();
            break;
        case 's':
            test_handshake();
            break;
        case 'a':
            test_aead();
            break;
        case 'f':
            test_frame();
            break;
        case 'r':
            test_seeded_random();
            break;
        case 'i':
            test_siphash();
            break;
        case 'm':
            test_stream();
            break;
        case '?':
            fprintf(stderr, "%s: %s\n", *argv, options.errmsg);
        case 'p':
            help();
            break;
        }
    }

}
