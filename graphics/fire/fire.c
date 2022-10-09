/*
 * Fire animation.
 *
 * This implements the fire effect similar to [0] but uses a different algorithm
 * which is closer to [1].
 *
 * [0]: https://github.com/fabiensanglard/DoomFirePSX
 * [1]: https://github.com/skeeto/webgl-fire
 */

#include <stdio.h>
#include <stdint.h>

/* Random seed. */
#ifndef SEED
# define SEED 0
#endif

/* Number of frames to render. */
#ifndef NFRAMES
# define NFRAMES 300
#endif

/* Strength of the horizontal wind. */
#ifndef HWIND
# define HWIND 0
#endif

/* Strength of the vertical wind. */
#ifndef VWIND
# define VWIND 0
#endif

static const unsigned char palette[] = {
    0x07, 0x07, 0x07, 0x1f, 0x07, 0x07, 0x2f, 0x0f, 0x07, 0x47, 0x0f, 0x07,
    0x57, 0x17, 0x07, 0x67, 0x1f, 0x07, 0x77, 0x1f, 0x07, 0x8f, 0x27, 0x07,
    0x9f, 0x2f, 0x07, 0xaf, 0x3f, 0x07, 0xbf, 0x47, 0x07, 0xc7, 0x47, 0x07,
    0xdf, 0x4f, 0x07, 0xdf, 0x57, 0x07, 0xdf, 0x57, 0x07, 0xd7, 0x5f, 0x07,
    0xd7, 0x5f, 0x07, 0xd7, 0x67, 0x0f, 0xcf, 0x6f, 0x0f, 0xcf, 0x77, 0x0f,
    0xcf, 0x7f, 0x0f, 0xcf, 0x87, 0x17, 0xc7, 0x87, 0x17, 0xc7, 0x8f, 0x17,
    0xc7, 0x97, 0x1f, 0xbf, 0x9f, 0x1f, 0xbf, 0x9f, 0x1f, 0xbf, 0xa7, 0x27,
    0xbf, 0xa7, 0x27, 0xbf, 0xaf, 0x2f, 0xb7, 0xaf, 0x2f, 0xb7, 0xb7, 0x2f,
    0xb7, 0xb7, 0x37, 0xcf, 0xcf, 0x6f, 0xdf, 0xdf, 0x9f, 0xef, 0xef, 0xc7,
    0xff, 0xff, 0xff
};
#define C 3
#define D (sizeof(palette) / sizeof(*palette) / C)

#define W 320
#define H 240
#define S 2
static signed char state[H][W];

static uint32_t
pcg32(void)
{
    static uint64_t s = SEED;
    s = s * UINT64_C(0x7e8c583ddff43de5) + UINT64_C(0xd0c5e4a55ca9db29);
    uint32_t r = s >> 32;
    r ^= r >> 16;
    r *= UINT32_C(0xc6ba12c7);
    return r;
}

/*
 * Hash a 16-bit integer.
 *
 * This function is used to enable parallel computation for a whole row of
 * cells. For each cell 16 random bits are sufficient.
 *
 * This hash function is from [0].
 *
 * [0]: https://github.com/skeeto/hash-prospector
 */
static uint16_t
hash16(uint16_t x)
{
    x ^= x >> 8;
    x *= UINT16_C(0x88b5);
    x ^= x >> 7;
    x *= UINT16_C(0xdb2d);
    x ^= x >> 9;
    return x;
}

static int
max(int x, int y)
{
    return x > y ? x : y;
}

static int
min(int x, int y)
{
    return x <= y ? x : y;
}

static void
step(void)
{
    for (int i = 0; i < H - 1; i++) {
        uint32_t rand = pcg32();
#pragma omp parallel for
        for (int j = 0; j < W; j++) {
            uint16_t r = hash16((rand >> 16) ^ j ^ rand);
            int di = (r & 3) + VWIND;
            if (di > 0) {
                int ds = -1 * ((r >> 2) & 1);
                int dj = (r >> 3) & 3;
                dj *= (r >> 5) & 1 ? 1 : -1;
                dj -= HWIND;
                int s = state[min(i + di, H - 1)][(j + dj + W - 1) % W];
                state[i][j] = max(0, s + ds);
            }
        }
    }
}

static int
render(void)
{
    static unsigned char image[H * S * W * S * C];
#pragma omp parallel for collapse(2)
    for (int i = 0; i < H * S; i++) {
        for (int j = 0; j < W * S; j++) {
            const unsigned char *color = palette + state[i / S][j / S] * C;
            int offset = i * W * S * C + j * C;
            for (int k = 0; k < C; k++)
                image[offset + k] = color[k];
        }
    }
    printf("P6\n%d %d\n255\n", W * S, H * S);
    return !fwrite(image, sizeof(image), sizeof(*image), stdout);
}

int
main(void)
{
    for (int j = 0; j < W; j++)
        state[H - 1][j] = D - 1;
    for (int k = 0; k < NFRAMES; k++) {
        if (k == NFRAMES / 5 * 3) {
            for (int j = 0; j < W; j++)
                state[H - 1][j] = 0;
        }
        step();
        if (render()) return 1;
    }
    return 0;
}

/* Local Variables: */
/* flycheck-gcc-language-standard: "c99" */
/* flycheck-gcc-pedantic: t */
/* flycheck-gcc-openmp: t */
/* End: */
