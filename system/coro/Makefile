.POSIX:
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g3 -fsanitize=undefined
CPPFLAGS =
LDFLAGS =
LDLIBS =
ETAGS = ctags -e

.PHONY: all clean

all: primes

primes: primes.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ primes.c $(LDLIBS)

TAGS: primes.c
	$(ETAGS) -o $@ primes.c

clean:
	rm -f primes TAGS
