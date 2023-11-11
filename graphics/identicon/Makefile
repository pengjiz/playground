.POSIX:
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g3 -fsanitize=address,undefined -fopenmp
CPPFLAGS =
LDFLAGS =
LDLIBS =
ETAGS = ctags -e

.PHONY: all clean

all: identicon

identicon: identicon.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ identicon.c $(LDLIBS)

TAGS: identicon.c
	$(ETAGS) -o $@ identicon.c

clean:
	rm -f identicon TAGS
