/*
 * Expose the output from another process.
 *
 * This is a rewrite from scratch of [0]. It additionally supports exposing the
 * output from multiple threads and newly created child processes of the target
 * process, as well as output redirection.
 *
 * This implementation requires Linux 5.3 or later. Besides, the redirecting
 * mode is currently experimental and only available on the x86-64 architecture.
 *
 * Please be aware that this program could greatly impact the performance of the
 * target process and might even make the target process fail unexpectedly. So
 * use with caution.
 *
 * [0]: https://github.com/rapiz1/catp
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>

/* Enable experimental support for output redirection. */
#ifdef USE_REDIRECT
# if defined(__x86_64__)
#  include <sys/reg.h>
#  define SCNR_NOP -1
#  define USER_SCNR ORIG_RAX * 8
#  define USER_SCRV RAX * 8
# else
#  undef USE_REDIRECT
# endif
#endif

#ifdef DEBUG
# if __GNUC__
#  define ASSERT(c) if (!(c)) __builtin_trap()
# else
#  define ASSERT(c) if (!(c)) *(volatile int *)NULL = 0
# endif
#else
# define ASSERT(c)
#endif

enum status {
    EXPOSE_OK = 0,
    EXPOSE_EXPECTED = 1,
    EXPOSE_MILD = 2,
    EXPOSE_MILD_ALT = 3,
    EXPOSE_SEVERE = -1,
    EXPOSE_SEVERE_ALT = -2
};

static int redirect;
static int quiet;
static char errstr[256] = {0};
#define E(...) snprintf(errstr, sizeof(errstr) - 1, __VA_ARGS__)
#define HT_ESLOTS 11
#define HT_NLIMIT (1 << 10)
#ifdef USE_REDIRECT
# define OPTSTR "arqh"
#else
# define OPTSTR "aqh"
#endif

static void
message(const char *fmt, ...)
{
    if (quiet) return;
    int e = errno;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    errno = e;
}

/*
 * Hash a 32-bit integer.
 *
 * This function is used for storing system call information of threads in the
 * internal hash table. Specifically, it is used to hash the thread ID.
 *
 * This hash function is from [0].
 *
 * [0]: https://github.com/skeeto/hash-prospector
 */
static uint32_t
hash32(uint32_t x)
{
    x ^= x >> 16;
    x *= UINT32_C(0x7feb352d);
    x ^= x >> 15;
    x *= UINT32_C(0x846ca68b);
    x ^= x >> 16;
    return x;
}

struct ht_slot {
    pid_t tid;
    int fd;
    uintptr_t src;
    size_t count;
};

static struct {
    int len;
    struct ht_slot slots[1 << HT_ESLOTS];
} ht = {0};

/*
 * Look up information for a thread in the internal hash table.
 *
 * This function is used to save and load system call information of threads. It
 * will return a pointer to the slot for the given thread ID. If the thread ID
 * is not found in the table and the table is full, it will return a null
 * pointer instead.
 *
 * The implementation is mostly from [0].
 *
 * [0]: https://nullprogram.com/blog/2022/08/08/
 */
static struct ht_slot *
ht_lookup(pid_t tid)
{
    ASSERT(tid > 0);
    static const uint16_t mask = (UINT16_C(1) << HT_ESLOTS) - 1;
    uint32_t hash = hash32(tid);
    uint16_t idx = hash;
    uint16_t step = (hash >> (32 - HT_ESLOTS)) | 1;
    while (1) {
        idx = (idx + step) & mask;
        if (ht.slots[idx].tid == tid) return ht.slots + idx;
        if (!ht.slots[idx].tid) {
            if (ht.len == HT_NLIMIT) return NULL;
            return ht.slots + idx;
        }
    }
}

static enum status
save_ctx(pid_t tid, int fd, uintptr_t src, size_t count)
{
    struct ht_slot *slot = ht_lookup(tid);
    if (!slot) return EXPOSE_SEVERE;
    ASSERT(!slot->tid);
    ASSERT(ht.len < HT_NLIMIT);
    ht.len++;
    slot->tid = tid;
    slot->fd = fd;
    slot->src = src;
    slot->count = count;
    return EXPOSE_OK;
}

static enum status
load_ctx(pid_t tid, int *fd, uintptr_t *src, size_t *count)
{
    struct ht_slot *slot = ht_lookup(tid);
    if (!slot || !slot->tid) return EXPOSE_EXPECTED;
    ASSERT(slot->tid == tid);
    if (fd) *fd = slot->fd;
    if (src) *src = slot->src;
    if (count) *count = slot->count;
    ASSERT(ht.len > 0);
    ht.len--;
    memset(slot, 0, sizeof(*slot));
    return EXPOSE_OK;
}

static pid_t
strtopid(const char *s)
{
    errno = 0;
    char *end;
    long n = strtol(s, &end, 10);
    if (errno || *end) return EXPOSE_SEVERE;
    if (n < 1 || n > INT_MAX) return EXPOSE_SEVERE_ALT;
    return n;
}

static enum status
ptrace_seize(pid_t pid, unsigned long opts)
{
    int r = ptrace(PTRACE_SEIZE, pid, 0, opts);
    if (r < 0) return EXPOSE_SEVERE;
    r = ptrace(PTRACE_INTERRUPT, pid, 0, 0);
    if (r < 0) return EXPOSE_SEVERE_ALT;
    return EXPOSE_OK;
}

static enum status
ptrace_wait(pid_t pid, int target)
{
    int r;
    int status;
    while ((r = waitpid(pid, &status, __WALL)) > 0) {
        ASSERT(!WIFCONTINUED(status));
        if (!WIFSTOPPED(status)) continue;
        if ((status >> 8) == target) break;

        int sig = WSTOPSIG(status);
        int req = PTRACE_CONT;
        switch (status >> 16) {
        case 0:
            break;
        case PTRACE_EVENT_STOP:
            switch (sig) {
            case SIGSTOP:
            case SIGTSTP:
            case SIGTTIN:
            case SIGTTOU:
                req = PTRACE_LISTEN;
                break;
            }
            sig = 0;
            break;
        default:
            sig = 0;
            break;
        }
        r = ptrace(req, pid, 0, sig);
        if (r < 0) break;
    }

    if (r < 0) return EXPOSE_SEVERE;
    return EXPOSE_OK;
}

static enum status
attach(pid_t pid, int all)
{
    int r;
    int cont = 0;
    pid_t tid = pid;
    unsigned long opts = PTRACE_O_TRACESYSGOOD;

    if (!all) {
        r = ptrace_seize(tid, opts);
        if (r < 0) goto eseize;
        return EXPOSE_OK;
    }

    /* Stop the process before seizing its existing threads to avoid racing
     * against thread creation and termination */
    r = ptrace_seize(tid, 0);
    if (r < 0) goto estop;
    r = ptrace_wait(tid, (PTRACE_EVENT_STOP << 8) | SIGTRAP);
    if (r < 0) goto estop;
    r = ptrace(PTRACE_DETACH, tid, 0, 0);
    if (r < 0) goto estop;
    /* TODO: Find out whether or not this would notify the parent process and
     * how to avoid that reliably if so. */
    r = tgkill(pid, pid, SIGSTOP);
    if (r < 0) goto estop;
    cont = 1;

    opts |= PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    /* TODO: Check if it is necessary to wait for the process to stop before
     * starting seizing threads. */
    r = ptrace_seize(tid, opts);
    if (r < 0) goto eseize;

    static const char tpl[] = "/proc/%d/task";
    char name[sizeof(tpl) + sizeof(pid_t) * 3];
    r = snprintf(name, sizeof(name) - 1, tpl, pid);
    if (r < 0) goto ethreads;
    DIR *d = opendir(name);
    if (!d) goto ethreads;

    errno = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;
        tid = strtopid(ent->d_name);
        if (tid < 0) {
            message("expose: warning: "
                    "entry %s skipped (failed to convert to thread ID)\n",
                    ent->d_name);
            errno = 0;
            continue;
        }
        if (tid == pid) continue;
        r = ptrace_seize(tid, opts);
        switch (r) {
        case EXPOSE_SEVERE:
            message("expose: warning: "
                    "thread %d skipped [errno %d]\n",
                    tid, errno);
            errno = 0;
            continue;
        case EXPOSE_SEVERE_ALT:
            goto eseize;
        }
    }
    if (errno) goto ethreads;

    r = tgkill(pid, pid, SIGCONT);
    if (r < 0) goto econt;
    return EXPOSE_OK;

ethreads:
    E("failed to get threads of process [errno %d]", errno);
    goto fail;
eseize:
    E("failed to seize thread %d [errno %d]", tid, errno);
    goto fail;
estop:
    E("failed to stop process [errno %d]", errno);
    goto fail;
econt:
    E("failed to restart process [errno %d]", errno);
    cont = 0;
    goto fail;

fail:
    if (cont) tgkill(pid, pid, SIGCONT);
    return EXPOSE_SEVERE;
}

static void *
pmemcpy(pid_t pid, void *dst, uintptr_t src, size_t n)
{
    struct iovec local = {dst, n};
    struct iovec remote = {(void *)src, n};
    ssize_t r = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (r < 0) return NULL;
    return dst;
}

static int
match_syscall(const struct ptrace_syscall_info *info)
{
    if (info->entry.nr != SYS_write) return 0;
    int fd = info->entry.args[0];
    return fd == STDOUT_FILENO || fd == STDERR_FILENO;
}

static enum status
handle_syscall(pid_t tid)
{
    int r;
    void *dst = NULL;
    struct ptrace_syscall_info info;
    r = ptrace(PTRACE_GET_SYSCALL_INFO, tid, sizeof(info), &info);
    if (r < 0) goto einfo;

    int fd;
    uintptr_t src;
    size_t count;
    switch (info.op) {
    case PTRACE_SYSCALL_INFO_ENTRY:
        if (!match_syscall(&info)) return EXPOSE_OK;
        fd = info.entry.args[0];
        src = info.entry.args[1];
        count = info.entry.args[2];
        r = save_ctx(tid, fd, src, count);
        if (r < 0) goto elimit;
        if (redirect) {
#ifdef USE_REDIRECT
            r = ptrace(PTRACE_POKEUSER, tid, USER_SCNR, SCNR_NOP);
#else
            ASSERT(0);
            r = 0;
#endif
            if (r < 0) goto escnr;
        }
        break;

    case PTRACE_SYSCALL_INFO_EXIT:
        r = load_ctx(tid, &fd, &src, &count);
        if (r) return EXPOSE_OK;
        int failed = info.exit.is_error;
        int muted = redirect && failed && info.exit.rval == -ENOSYS;
        if (failed && !muted) goto enotme;
        if (!failed) count = info.exit.rval;

        dst = malloc(count);
        if (!dst) goto ewrite;
        if (!pmemcpy(tid, dst, src, count)) goto ewrite;
        ssize_t n = write(fd, dst, count);
        if (muted) {
#ifdef USE_REDIRECT
            r = ptrace(PTRACE_POKEUSER, tid, USER_SCRV, n < 0 ? 0 : n);
#else
            ASSERT(0);
            r = 0;
#endif
            if (r < 0) goto escrv;
        }
        if (n < 0) goto ewrite;
        if ((size_t)n < count) goto epartial;
        break;
    }

    free(dst);
    return EXPOSE_OK;

einfo:
    E("failed to get system call information [errno %d]", errno);
    r = errno == ESRCH ? EXPOSE_EXPECTED : EXPOSE_MILD;
    goto fail;
elimit:
    E("too many threads");
    r = EXPOSE_MILD;
    goto fail;
ewrite:
    E("failed to write output [errno %d]", errno);
    r = EXPOSE_MILD;
    goto fail;
epartial:
    E("partial writes happened");
    r = EXPOSE_MILD_ALT;
    goto fail;
enotme:
    E("errors happened in thread");
    r = EXPOSE_MILD;
    goto fail;
escnr:
    E("failed to redirect output [errno %d]", errno);
    r = errno == ESRCH ? EXPOSE_EXPECTED : EXPOSE_MILD_ALT;
    goto fail;
escrv:
    E("failed to redirect output [errno %d]", errno);
    r = errno == ESRCH ? EXPOSE_EXPECTED : EXPOSE_SEVERE;
    goto fail;

fail:
    free(dst);
    return r;
}

static enum status
dispatch(pid_t tid, int status)
{
    int r;
    int cleanup = 0;
    ASSERT(!WIFCONTINUED(status));
    if (!WIFSTOPPED(status)) {
        r = EXPOSE_OK;
        /* Probably unnecessary but just in case */
        cleanup = 1;
        goto finish;
    }

    int sig = WSTOPSIG(status);
    int req = PTRACE_SYSCALL;
    switch (status >> 16) {
    case 0:
        if (sig == (0x80 | SIGTRAP)) {
            r = handle_syscall(tid);
            switch (r) {
            case EXPOSE_MILD:
                message("expose: warning: "
                        "output from thread %d skipped (%s)\n",
                        tid, errstr);
                cleanup = 1;
                break;
            case EXPOSE_MILD_ALT:
                message("expose: warning: "
                        "failed partly for thread %d (%s)\n",
                        tid, errstr);
                break;
            case EXPOSE_EXPECTED:
                r = EXPOSE_OK;
                cleanup = 1;
                goto finish;
            case EXPOSE_SEVERE:
                r = EXPOSE_SEVERE;
                cleanup = 1;
                goto finish;
            }
            sig = 0;
        }
        break;

    case PTRACE_EVENT_STOP:
        switch (sig) {
        case SIGSTOP:
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
            req = PTRACE_LISTEN;
            break;
        }
        sig = 0;
        break;

    default:
        sig = 0;
        break;
    }

    r = ptrace(req, tid, 0, sig);
    if (r < 0 && errno != ESRCH) {
        E("failed to restart thread %d [errno %d]", tid, errno);
        r = EXPOSE_SEVERE;
        goto finish;
    }
    r = EXPOSE_OK;

finish:
    if (cleanup) load_ctx(tid, NULL, NULL, NULL);
    return r;
}

static void
usage(FILE *f, int brief)
{
    fprintf(f, "Usage: expose [-" OPTSTR "] PID\n");
    if (brief) return;
    fprintf(f, "Expose the output from another process.\n");
    fputc('\n', f);
    fprintf(f, "Arguments:\n");
    fprintf(f, "  PID   target process ID\n");
    fputc('\n', f);
    fprintf(f, "Options:\n");
    fprintf(f, "  -a    expose all threads and new child processes\n");
#ifdef USE_REDIRECT
    fprintf(f, "  -r    enable experimental output redirecting mode\n");
#endif
    fprintf(f, "  -q    suppress messages while exposing\n");
    fprintf(f, "  -h    print this help message and exit\n");
}

int
main(int argc, char **argv)
{
    pid_t pid;
    int all = 0;
    redirect = 0;
    quiet = 0;

    int opt;
    opterr = 0;
    while ((opt = getopt(argc, argv, OPTSTR)) != -1) {
        switch (opt) {
        case 'a':
            all = 1;
            break;
#ifdef USE_REDIRECT
        case 'r':
            redirect = 1;
            break;
#endif
        case 'q':
            quiet = 1;
            break;
        case 'h':
            usage(stdout, 0);
            return EXIT_SUCCESS;
        case '?':
            fprintf(stderr, "expose: fatal: unknown option %c\n", optopt);
            usage(stderr, 1);
            return EXIT_FAILURE;
        default:
            usage(stderr, 1);
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "expose: fatal: too few arguments\n");
        usage(stderr, 1);
        return EXIT_FAILURE;
    }
    if ((optind + 1) < argc) {
        fprintf(stderr, "expose: fatal: too many arguments\n");
        usage(stderr, 1);
        return EXIT_FAILURE;
    }
    pid = strtopid(argv[optind]);
    if (pid < 0) {
        message("expose: fatal: invalid PID %s\n", argv[optind]);
        return EXIT_FAILURE;
    }

    int r = attach(pid, all);
    if (r < 0) {
        message("expose: fatal: %s\n", errstr);
        return EXIT_FAILURE;
    }
    while (1) {
        int status;
        pid_t tid = waitpid(-1, &status, __WALL);
        switch (tid) {
        case -1:
            if (errno == ECHILD) return EXIT_SUCCESS;
            message("expose: fatal: "
                    "failed to poll threads [errno %d]\n",
                    errno);
            return EXIT_FAILURE;
        case 0:
            ASSERT(0);
            return EXIT_FAILURE;
        default:
            r = dispatch(tid, status);
            if (r < 0) {
                message("expose: fatal: %s\n", errstr);
                return EXIT_FAILURE;
            }
            break;
        }
    }
}

/* Local Variables: */
/* flycheck-gcc-language-standard: "c99" */
/* flycheck-gcc-pedantic: t */
/* flycheck-gcc-definitions: ("DEBUG" "USE_REDIRECT") */
/* End: */
