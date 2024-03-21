.POSIX:
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g3 -fsanitize=undefined
CPPFLAGS =
LDFLAGS =
LDLIBS =
ETAGS = ctags -e

.PHONY: all clean

all: coro

coro: coro.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ coro.c $(LDLIBS)

TAGS: coro.c
	$(ETAGS) -o $@ coro.c

clean:
	rm -f coro TAGS
