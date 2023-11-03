.POSIX:
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g3 -fsanitize=address,undefined -fopenmp
CPPFLAGS =
LDFLAGS =
LDLIBS =
ETAGS = ctags -e

.PHONY: all clean

all: fire

fire: fire.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ fire.c $(LDLIBS)

fire.mp4: fire
	./fire | ffmpeg -y -framerate 30 -i - $@

TAGS: fire.c
	$(ETAGS) -o $@ fire.c

clean:
	rm -f fire fire.mp4 TAGS
