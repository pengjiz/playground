/*
 * Simple asynchronous chat server using stackful coroutines.
 *
 * This program is to demonstrate the capability and one potential use case of
 * the rather minimal coroutine implementation in [0]. The chat server is rather
 * rudimentary, and perhaps should not be used for anything serious.
 *
 * This program uses a few GNU C extensions, and should work with GCC and Clang.
 * Besides, it depends on liburing. That library is quite nice, but I am
 * inclined to drop the dependency for simplicity.
 *
 * [0]: https://github.com/skeeto/scratch/blob/master/misc/coro.c
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <netinet/in.h>
#include <liburing.h>

#ifdef NDEBUG
# define ASSERT(c)
#else
# define ASSERT(c) if (!(c)) __builtin_trap()
#endif

#define CORO_CAP (1 << 15)
#define BUF_CAP (1 << 11)
#define LINE_CAP (1 << 9)
#define RING_CAP 128
#define PORT 18017
static volatile sig_atomic_t running = 1;
static int cleanup = 0;

enum status {
    CHATD_OK = 0,
    CHATD_RETRY = 1,
    CHATD_LOST = 2,
    CHATD_ERROR = -1,
};

struct coro {
    uintptr_t rip;
    uintptr_t rsp;
    uintptr_t save[6];
    __attribute__((aligned(16))) char stack[CORO_CAP];
};

static struct coro *
coro_new(void (*fn)(void *))
{
    struct coro *c = calloc(1, sizeof(*c));
    if (!c) return 0;
    c->rip = (uintptr_t)fn;
    c->rsp = (uintptr_t)(c->stack + CORO_CAP - 8);
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

struct client {
    int id;
    int fd;
    struct io_uring *ring;
    struct coro *coro;
    struct client *next;
    struct client **head;
};

struct server {
    int fd;
    struct io_uring *ring;
    struct coro *coro;
    struct client *clients;
};

static struct client *
client_new(struct server *s, int id, int fd)
{
    struct client *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->id = id;
    c->fd = fd;
    c->ring = s->ring;
    c->next = s->clients;
    s->clients = c;
    c->head = &s->clients;
    return c;
}

static struct server *
server_new(int port, struct io_uring *ring)
{
    int r;
    int fd = -1;
    struct server *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) goto fail;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(port),
        .sin6_addr = in6addr_loopback,
    };
    r = bind(fd, (void *)&addr, sizeof(addr));
    if (r < 0) goto fail;
    r = listen(fd, INT_MAX);
    if (r < 0) goto fail;

    s->fd = fd;
    s->ring = ring;
    return s;

fail:
    free(s);
    if (fd > 0) close(fd);
    return NULL;
}

static int
format_prefix(const struct client *restrict c, char *restrict dst)
{
    int id = c->id;
    char buf[sizeof(id) * 4];
    char *end = buf + sizeof(buf);
    char *beg = end;
    *--beg = ' ';
    *--beg = '>';
    do {
        *--beg = id % 10 + '0';
    } while (id /= 10);
    memcpy(dst, beg, end - beg);
    return end - beg;
}

static void
chat(void *arg)
{
    struct client *c = arg;
    struct io_uring_sqe *sqe = NULL;
    struct io_uring_cqe *cqe = NULL;

    char line[LINE_CAP];
    int npre = format_prefix(c, line);
    ASSERT(npre > 0);
    char *eol = line + npre;

    char buf[BUF_CAP];
    char *bob = buf;
    char *eob = bob;

    while (1) {
        if (bob == eob) {
            bob = eob = buf;
            do {
                sqe = io_uring_get_sqe(c->ring);
                if (!sqe) yield(c->coro, &(enum status){CHATD_RETRY});
            } while (!sqe);
            io_uring_prep_read(sqe, c->fd, buf, sizeof(buf), 0);
            io_uring_sqe_set_data(sqe, c->coro);
            cqe = yield(c->coro, &(enum status){CHATD_OK});

            if (cqe->res > 0) {
                eob += cqe->res;
            } else {
                switch (-cqe->res) {
                case EINTR:
                    continue;
                default:
                    c->id |= ~(-1U >> 1);
                    yield(c->coro, &(enum status){CHATD_LOST});
                    ASSERT(0);
                }
            }
        }

        ASSERT(bob < eob);
        while (bob != eob && eol != line + LINE_CAP - 1) {
            if (*bob == '\n') break;
            *eol++ = *bob++;
        }
        if (bob == eob) continue;
        ASSERT(eol < line + LINE_CAP);
        if (*bob == '\n') bob++;
        *eol++ = '\n';

        int len = eol - line;
        struct client *p = *c->head;
        while (p) {
            if (p == c || p->id & ~(-1U >> 1)) {
                p = p->next;
                continue;
            }

            int n = 0;
            while (n < len) {
                do {
                    sqe = io_uring_get_sqe(c->ring);
                    if (!sqe) yield(c->coro, &(enum status){CHATD_RETRY});
                } while (!sqe);
                io_uring_prep_write(sqe, p->fd, line + n, len - n, 0);
                io_uring_sqe_set_data(sqe, c->coro);
                cqe = yield(c->coro, &(enum status){CHATD_OK});
                if (cqe->res < 0) break;
                n += cqe->res;
            }
            p = p->next;
        }
        eol = line + npre;
    }
}

static void
login(void *arg)
{
    struct server *s = arg;
    struct io_uring_sqe *sqe = NULL;
    struct io_uring_cqe *cqe = NULL;
    int id = 0;
    int fd = -1;
    struct client *c = NULL;

    while (1) {
        fd = -1;
        c = NULL;
        do {
            sqe = io_uring_get_sqe(s->ring);
            if (!sqe) yield(s->coro, &(enum status){CHATD_RETRY});
        } while (!sqe);
        io_uring_prep_accept(sqe, s->fd, NULL, NULL, 0);
        io_uring_sqe_set_data(sqe, s->coro);
        cqe = yield(s->coro, &(enum status){CHATD_OK});

        if (cqe->res < 0) {
            switch (-cqe->res) {
            case EINTR:
                continue;
            default:
                goto fail;
            }
        } else {
            fd = cqe->res;
            c = client_new(s, id++, cqe->res);
            if (!c) goto fail;
            c->coro = coro_new(chat);
            if (!c->coro) goto fail;
            enum status r;
            do {
                r = *(enum status *)yield(c->coro, c);
                switch (r) {
                case CHATD_OK:
                    break;
                case CHATD_RETRY:
                    yield(s->coro, &r);
                    break;
                case CHATD_LOST:
                    ASSERT(0);
                case CHATD_ERROR:
                    goto fail;
                }
            } while (r == CHATD_RETRY);
        }
    }

fail:
    if (fd > 0) close(fd);
    if (c) free(c->coro);
    free(c);
    yield(s->coro, &(enum status){CHATD_ERROR});
    ASSERT(0);
}

static void
handle_sigterm(int sig)
{
    (void)sig;
    running = 0;
}

int
main(void)
{
    int e = 1;
    int r;
    signal(SIGPIPE, SIG_IGN);
    {
        struct sigaction sa = {.sa_handler = handle_sigterm};
        r = sigaction(SIGTERM, &sa, 0);
        if (r < 0) return EXIT_FAILURE;
    }

    struct io_uring ring[1];
    r = io_uring_queue_init(RING_CAP, ring, 0);
    if (r < 0) return EXIT_FAILURE;
    struct server *server = server_new(PORT, ring);
    if (!server) goto done;
    server->coro = coro_new(login);
    if (!server->coro) goto done;
    yield(server->coro, server);

    struct io_uring_sqe *sqe = NULL;
    struct io_uring_cqe *cqe = NULL;
    struct coro *coro = NULL;
    for (size_t i = 0; running; i++) {
        r = io_uring_submit(ring);
        if (r < 0) goto done;
        r = io_uring_wait_cqe(ring, &cqe);
        if (r == -EINTR) {
            continue;
        } else if (r < 0) {
            goto done;
        }

        if (coro) {
            cqe = NULL;
        } else {
            coro = io_uring_cqe_get_data(cqe);
        }
        if (coro) {
            r = *(enum status *)yield(coro, cqe);
            switch (r) {
            case CHATD_OK:
                break;
            case CHATD_RETRY:
                continue;
            case CHATD_LOST:
                cleanup = 1;
                break;
            case CHATD_ERROR:
                goto done;
            }
        }
        coro = NULL;
        if (cqe) io_uring_cqe_seen(ring, cqe);

        if (cleanup && !(i % 32)) {
            r = io_uring_submit(ring);
            if (r < 0) goto done;
            struct client **p = &server->clients;
            while (*p) {
                struct client *c = *p;
                if (!(c->id & ~(-1U >> 1))) {
                    p = &c->next;
                    continue;
                }
                *p = c->next;

                sqe = io_uring_get_sqe(ring);
                ASSERT(sqe);
                io_uring_prep_close(sqe, c->fd);
                io_uring_sqe_set_data(sqe, NULL);
                free(c->coro);
                free(c);
            }
            cleanup = 0;
        }
    }
    e = 0;

done:
    io_uring_queue_exit(ring);
    if (server) {
        close(server->fd);
        free(server->coro);
        struct client *c = server->clients;
        while (c) {
            struct client *d = c;
            c = c->next;
            close(d->fd);
            free(d->coro);
            free(d);
        }
    }
    free(server);
    return e ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* Local Variables: */
/* flycheck-clang-language-standard: "c99" */
/* flycheck-clang-pedantic: t */
/* End: */
