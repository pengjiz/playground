.POSIX:
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g3 -fsanitize=address,undefined
CPPFLAGS = -DUSE_REDIRECT
LDFLAGS =
LDLIBS =
ETAGS = ctags -e

.PHONY: all clean

all: expose

expose: expose.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ expose.c $(LDLIBS)

TAGS: expose.c
	$(ETAGS) -o $@ expose.c

clean:
	rm -f expose TAGS
