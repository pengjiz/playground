/*
 * Prime number generator using stackful coroutines.
 *
 * This is basically [0] ported to x86-64 Linux. The implementation uses a few
 * GNU C extensions, and should work with GCC and Clang. Note that this program
 * could be optionally compiled for a freestanding environment without using any
 * standard system startup files or libraries.
 *
 * The coroutine implementation is definitely neat, but it also has a few
 * limitations. Frankly it might be inappropriate for serious projects.
 *
 * [0]: https://github.com/skeeto/scratch/blob/master/misc/coro.c
 */

typedef long size;
typedef unsigned long uintptr;

#if __STDC_HOSTED__
# include <unistd.h>
# include <sys/mman.h>
#else
__asm__ (".globl _start\n"
         "_start:\n\t"
         "call main\n\t"
         "mov %eax, %edi\n\t"
         "mov $60, %eax\n\t"
         "syscall");

static size
write(int fd, const void *buf, size count)
{
    size r;
    __asm__ volatile ("syscall"
                      : "=a"(r)
                      : "a"(1), "D"(fd), "S"(buf), "d"(count)
                      : "rcx", "r11", "memory");
    return r;
}

static void *
mmap(void *addr, size length, int prot, int flags, int fd, size offset)
{
    void *r;
    register int r10 __asm__("r10") = flags;
    register int r8 __asm__("r8") = fd;
    register size r9 __asm__("r9") = offset;
    __asm__ volatile ("syscall"
                      : "=a"(r)
                      : "a"(9), "D"(addr), "S"(length), "d"(prot),
                        "r"(r10), "r"(r8), "r"(r9)
                      : "rcx", "r11", "memory");
    return r;
}
#endif

#ifdef NDEBUG
# define ASSERT(c)
#else
# define ASSERT(c) if(!(c)) *(volatile int *)0 = 0
#endif

#define ARENA_CAP (1 << 24)
#define CORO_CAP (1 << 10)
#define LINE_CAP 512
#define CELL_CAP 32

#define W 8
#define C 10
#define N 5000

struct arena {
    char *beg;
    char *end;
};

__attribute__((malloc, alloc_size(2, 3), alloc_align(4)))
static void *
alloc(struct arena *a, size count, size one, size align)
{
    size padding = (uintptr)a->end & align;
    size total = count * one;
    if ((total + padding) > (a->end - a->beg)) return 0;
    char *r = a->end -= total + padding;
    for (size i = 0; i < total; i++) r[i] = 0;
    return r;
}

struct coro {
    unsigned long long rip;
    unsigned long long rsp;
    unsigned long long save[6];
};

static struct coro *
coro_new(struct arena *a, void (*fn)(void *))
{
    struct coro *c = alloc(a, 1, sizeof(*c), __alignof__(*c));
    if (!c) return 0;
    char *stack = alloc(a, CORO_CAP / 16, 16, 16);
    if (!stack) return 0;
    c->rip = (uintptr)fn;
    c->rsp = (uintptr)(stack + CORO_CAP - 8);
    ASSERT(!((c->rsp + 8) % 16));
    return c;
}

__attribute__((naked))
static void *
yield(__attribute__((unused)) struct coro *c,
      __attribute__((unused)) void *arg)
{
    __asm__ ("pop %r11\n\t"
             "xchg %r11, 0(%rdi)\n\t"
             "xchg %rsp, 8(%rdi)\n\t"
             "xchg %rbx, 16(%rdi)\n\t"
             "xchg %rbp, 24(%rdi)\n\t"
             "xchg %r12, 32(%rdi)\n\t"
             "xchg %r13, 40(%rdi)\n\t"
             "xchg %r14, 48(%rdi)\n\t"
             "xchg %r15, 56(%rdi)\n\t"
             "mov %rsi, %rdi\n\t"
             "mov %rsi, %rax\n\t"
             "jmp *%r11");
}

struct filter {
    long prime;
    struct coro *prev;
    struct coro *next;
};

struct query {
    long num;
    struct coro *prev;
};

static void
is_prime(void *arg)
{
    struct filter p = *(struct filter *)arg;
    int r = 0;
    while (1) {
        ASSERT(p.next);
        struct query *q = yield(p.next, &r);
        p.next = q->prev;
        if (!(q->num % p.prime)) {
            r = 0;
        } else if (!p.prev) {
            r = 1;
        } else {
            r = *(int *)yield(p.prev, &(struct query){q->num, p.prev});
        }
    }
}

static void
next_prime(void *arg)
{
    struct coro *c = arg;
    struct arena *a = yield(c, 0);
    struct query q = {2, 0};
    int r = 1;
    while (1) {
        if (r) {
            yield(c, &q.num);
            struct coro *p = coro_new(a, is_prime);
            if (!p) yield(c, 0);
            yield(p, &(struct filter){q.num, q.prev, p});
            q.prev = p;
        }
        q.num++;
        ASSERT(q.prev);
        r = *(int *)yield(q.prev, &q);
    }
}

static void
format_cell(char **dst, long num)
{
    static char buf[CELL_CAP];
    char *end = buf + sizeof(buf);
    char *beg = end;
    ASSERT(num >= 0);
    do {
        *--beg = num % 10 + '0';
    } while (num /= 10);
    *--beg = ' ';
    while ((end - beg) < W) *--beg = ' ';
    while (beg < end) *(*dst)++ = *beg++;
}

int
main(void)
{
    void *buf = mmap(0, ARENA_CAP, 3, 0x22, -1, 0);
    if ((uintptr)buf > (uintptr)-4096) return 1;
    struct arena a;
    a.beg = buf;
    a.end = a.beg + ARENA_CAP;

    static char line[LINE_CAP];
    char *end = line;
    struct coro *c = coro_new(&a, next_prime);
    if (!c) return 1;
    yield(c, c);
    for (int i = 0; i < N; i++) {
        long *num = yield(c, &a);
        if (!num) return 1;
        format_cell(&end, *num);
        if ((i + 1) % C && (i + 1) < N) continue;
        *end++ = '\n';
        if (write(1, line, end - line) < 0) return 1;
        end = line;
    }
    return 0;
}

/* Local Variables: */
/* flycheck-clang-language-standard: "c99" */
/* flycheck-clang-pedantic: t */
/* End: */
