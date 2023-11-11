/*
 * Identicon generator.
 *
 * This implements a simple identicon generator based on the Game of Life update
 * rules by Conway. Specifically, it uses the hash value of the input string as
 * the initial state, and update the state a few times with the Game of Life
 * rules. The final state is then used to create the identicon.
 *
 * Note that this implementation uses SSE2 instructions, which should be
 * available with all x86-64 processors.
 */

#define _XOPEN_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <immintrin.h>

/* Scale for rendering. */
#ifndef SCALE
# define SCALE 20
#endif

/* Seed for the hash function. */
#ifndef SEED
# define SEED 0x7532435a8e53329bU
#endif

#define N 10
#define QUOTE(s) #s
#define STR(s) QUOTE(s)
#define FATAL(...) fprintf(stderr, "identicon: fatal: " __VA_ARGS__)

#define B(r, n) ((r >> n) & 1)
#define M(r) B(r, 6), B(r, 5), B(r, 4), B(r, 3), B(r, 2), B(r, 1)
#define C(r) B(r, 7), M(r), B(r, 0)
#define L(r) 0, B(r, 7), M(r)
#define R(r) M(r), B(r, 0), B(r, 0)

static uint64_t
hash(const char *s, int len)
{
    uint64_t r = SEED;
    for (int i = 0; i < len; i++) {
        r ^= s[i] & 0xff;
        r *= 0x37dd2e1df700849dU;
    }
    return r;
}

static unsigned long long
step(unsigned long long state)
{
    unsigned long long next = 0;
#pragma omp parallel for reduction(|:next)
    for (int i = 0; i < 8; i += 2) {
        unsigned char r0 = i > 0 ? (state >> (8 * (8 - i))) & 0xff : 0;
        unsigned char r1 = (state >> (8 * (7 - i))) & 0xff;
        unsigned char r2 = (state >> (8 * (6 - i))) & 0xff;
        unsigned char r3 = i < 6 ? (state >> (8 * (5 - i))) & 0xff : r2;

        __m128i n = _mm_set_epi8(L(r0), L(r1));
        n = _mm_add_epi8(n, _mm_set_epi8(C(r0), C(r1)));
        n = _mm_add_epi8(n, _mm_set_epi8(R(r0), R(r1)));
        n = _mm_add_epi8(n, _mm_set_epi8(L(r1), L(r2)));
        n = _mm_add_epi8(n, _mm_set_epi8(R(r1), R(r2)));
        n = _mm_add_epi8(n, _mm_set_epi8(L(r2), L(r3)));
        n = _mm_add_epi8(n, _mm_set_epi8(C(r2), C(r3)));
        n = _mm_add_epi8(n, _mm_set_epi8(R(r2), R(r3)));

        unsigned long long u = (r1 << 8) | r2;
        u &= _mm_movemask_epi8(_mm_cmpeq_epi8(n, _mm_set1_epi8(2)));
        u |= _mm_movemask_epi8(_mm_cmpeq_epi8(n, _mm_set1_epi8(3)));
        next |= u << 8 * (6 - i);
    }
    return next;
}

static void
usage(FILE *f, int brief)
{
    fprintf(f, "Usage: identicon [-h] [-n NSTEPS] INPUT\n");
    if (brief) return;
    fprintf(f, "Generate identicon from an input string.\n");
    fputc('\n', f);
    fprintf(f, "Arguments:\n");
    fprintf(f, "  INPUT       string to generate identicon from\n");
    fputc('\n', f);
    fprintf(f, "Options:\n");
    fprintf(f, "  -n NSTEPS   number of update steps to execute"
            " [default: " STR(N) "]\n");
    fprintf(f, "  -h          print this help message and exit\n");
}

int
main(int argc, char **argv)
{
    int nsteps = N;
    char *input;
    int opt;
    opterr = 0;
    while ((opt = getopt(argc, argv, "n:h")) != -1) {
        switch (opt) {
        case 'n':
            errno = 0;
            char *end;
            long n = strtol(optarg, &end, 10);
            if (errno || *end || n < 0 || n > INT_MAX) {
                FATAL("invalid number of steps %s\n", optarg);
                return EXIT_FAILURE;
            }
            nsteps = n;
            break;
        case 'h':
            usage(stdout, 0);
            return EXIT_SUCCESS;
        case '?':
            FATAL("unknown option %c\n", optopt);
            usage(stderr, 1);
            return EXIT_FAILURE;
        default:
            usage(stderr, 1);
            return EXIT_FAILURE;
        }
    }
    if (optind >= argc) {
        FATAL("too few arguments\n");
        usage(stderr, 1);
        return EXIT_FAILURE;
    }
    if ((optind + 1) < argc) {
        FATAL("too many arguments\n");
        usage(stderr, 1);
        return EXIT_FAILURE;
    }
    input = argv[optind];

    unsigned long long state = hash(input, strlen(input));
    for (int i = 0; i < nsteps; i++) state = step(state);
    printf("P1\n%d %d\n", 8 * 2 * SCALE, 8 * 2 * SCALE);
    for (int j = 0; j < 8 * 2 * SCALE; j++) {
        for (int i = 0; i < 8 * 2 * SCALE; i++) {
            int x = i / SCALE;
            int y = j / SCALE;
            int r = (x < 8) ^ (y < 8);
            x = x < 8 ? x : 15 - x;
            y = y < 8 ? y : 15 - y;
            int v = (state >> (8 * (7 - y) + (7 - x))) & 1;
            v = r ? !v : v;
            putchar('0' + v);
            putchar('\n');
        }
    }
    return EXIT_SUCCESS;
}

/* Local Variables: */
/* flycheck-disabled-checkers: (c/c++-clang) */
/* flycheck-gcc-language-standard: "c99" */
/* flycheck-gcc-pedantic: t */
/* flycheck-gcc-openmp: t */
/* End: */
