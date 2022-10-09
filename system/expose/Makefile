.POSIX:
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -Og -g
CPPFLAGS = -DDEBUG -DUSE_REDIRECT
LDFLAGS =
LDLIBS =

.PHONY: all clean

all: expose

expose: expose.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ expose.c $(LDLIBS)

TAGS: expose.c
	ctags -f $@ -e expose.c

clean:
	rm -f expose TAGS
