BASEFLAGS=-Wall -Wextra -std=c99 -Wpedantic -Wuninitialized -Wundef -Wcast-align -Wstrict-overflow=2 -Wwrite-strings -Wno-format-nonliteral
DEBUGFLAGS=-ggdb -g3 -O0
RELEASEFLAGS=-s -O3 -march=native -flto -DNDEBUG
CLIBS=-lcrypto
EXEC=cobfs4
DEPS=$(EXEC).d
SRCS=elligator.c hmac.c packet.c
TEST_SRCS=test_main.c test_elligator.c test_hmac.c
HEADWILD=$(wildcard *.h)

debug release: all

all: main test

main: $(patsubst %.c, %.o, $(SRCS))

test: $(patsubst %.c, %.o, $(SRCS)) $(patsubst %.c, %.o, $(TEST_SRCS))
	$(CC) $(CFLAGS) $^ $(CLIBS) -o $(EXEC)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $(patsubst %.c, %.o, $<)

$(DEPS): $(SRCS) $(HEADWILD)
	@$(CC) $(CFLAGS) -MM $(SRCS) > $(DEPS)

ifneq ($(MAKECMDGOALS), clean)
-include $(DEPS)
endif

ifeq (,$(filter debug, $(MAKECMDGOALS)))
$(eval CFLAGS := $(BASEFLAGS) $(RELEASEFLAGS))
else
$(eval CFLAGS := $(BASEFLAGS) $(DEBUGFLAGS))
endif

.PHONY: clean

clean:
	$(RM) $(EXEC) $(wildcard *.o) $(wildcard *.d)

