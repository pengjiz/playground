.POSIX:
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g3 -fsanitize=undefined
CPPFLAGS =
LDFLAGS =
LDLIBS = -luring
ETAGS = ctags -e

.PHONY: all clean

all: primes chatd

primes: primes.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ primes.c $(LDLIBS)

chatd: chatd.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ chatd.c $(LDLIBS)

TAGS: primes.c chatd.c
	$(ETAGS) -o $@ primes.c chatd.c

clean:
	rm -f primes chatd TAGS
