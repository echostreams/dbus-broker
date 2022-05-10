/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#if defined(__linux__)
#include <linux/oom.h>
#include <pthread.h>
#endif
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#if defined(__linux__)
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#endif
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "alloc-util.h"
#include "architecture.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "locale-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_sched.h"
#include "missing_syscall.h"
#include "namespace-util.h"
#include "path-util.h"
#include "process-util.h"
#if defined(__linux__)
#include "raw-clone.h"
#endif
#include "rlimit-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "terminal-util.h"
#include "user-util.h"
#include "utf8.h"

#if defined(_MSC_VER)

/* We use the Windows header's Interlocked*64 functions instead of the
 * _Interlocked*64 intrinsics wherever we can, as support for the latter varies
 * with target CPU, whereas Windows headers take care of all portability
 * issues: using intrinsics where available, falling back to library
 * implementations where not.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <windows.h>
#include <intrin.h>
#include <assert.h>
 /* MSVC supports decltype keyword, but it's only supported on C++ and doesn't
  * quite work here; and if a C++-only solution is worthwhile, then it would be
  * better to use templates / function overloading, instead of decltype magic.
  * Therefore, we rely on implicit casting to LONGLONG for the functions that return
  */

#define __sync_val_compare_and_swap(_v, _old, _new) (\
   sizeof *(_v) == sizeof(char)    ? _InterlockedCompareExchange8 ((char *)   (_v), (char)   (_new), (char)   (_old)) : \
   sizeof *(_v) == sizeof(short)   ? _InterlockedCompareExchange16((short *)  (_v), (short)  (_new), (short)  (_old)) : \
   sizeof *(_v) == sizeof(long)    ? _InterlockedCompareExchange  ((long *)   (_v), (long)   (_new), (long)   (_old)) : \
   sizeof *(_v) == sizeof(__int64) ? InterlockedCompareExchange64 ((__int64 *)(_v), (__int64)(_new), (__int64)(_old)) : \
                                     (assert(!"should not get here"), 0))


#endif


/* The cached PID, possible values:
 *
 *     == UNSET [0]  → cache not initialized yet
 *     == BUSY [-1]  → some thread is initializing it at the moment
 *     any other     → the cached PID
 */

#define CACHED_PID_UNSET ((pid_t) 0)
#define CACHED_PID_BUSY ((pid_t) -1)

static pid_t cached_pid = CACHED_PID_UNSET;

void reset_cached_pid(void) {
    /* Invoked in the child after a fork(), i.e. at the first moment the PID changed */
    cached_pid = CACHED_PID_UNSET;
}

pid_t getpid_cached(void) {
    static bool installed = false;
    pid_t current_value;

    /* getpid_cached() is much like getpid(), but caches the value in local memory, to avoid having to invoke a
     * system call each time. This restores glibc behaviour from before 2.24, when getpid() was unconditionally
     * cached. Starting with 2.24 getpid() started to become prohibitively expensive when used for detecting when
     * objects were used across fork()s. With this caching the old behaviour is somewhat restored.
     *
     * https://bugzilla.redhat.com/show_bug.cgi?id=1443976
     * https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=c579f48edba88380635ab98cb612030e3ed8691e
     */

    current_value = __sync_val_compare_and_swap(&cached_pid, CACHED_PID_UNSET, CACHED_PID_BUSY);

    switch (current_value) {

    case CACHED_PID_UNSET: { /* Not initialized yet, then do so now */
        pid_t new_pid;

        new_pid = raw_getpid();

        if (!installed) {
            /* __register_atfork() either returns 0 or -ENOMEM, in its glibc implementation. Since it's
             * only half-documented (glibc doesn't document it but LSB does — though only superficially)
             * we'll check for errors only in the most generic fashion possible. */
#if defined(__linux__)
            if (pthread_atfork(NULL, NULL, reset_cached_pid) != 0) {
                /* OOM? Let's try again later */
                cached_pid = CACHED_PID_UNSET;
                return new_pid;
            }
#endif
            installed = true;
        }

        cached_pid = new_pid;
        return new_pid;
    }

    case CACHED_PID_BUSY: /* Somebody else is currently initializing */
        return raw_getpid();

    default: /* Properly initialized */
        return current_value;
    }
}


bool pid_is_alive(pid_t pid) {
    int r;

    /* Checks whether a PID is still valid and not a zombie */

    if (pid < 0)
        return false;

    if (pid <= 1) /* If we or PID 1 would be a zombie, this code would not be running */
        return true;

    if (pid == getpid_cached())
        return true;

#if 0
    r = get_process_state(pid);
    //if (IN_SET(r, -ESRCH, 'Z'))
    if ((r == -ESRCH || r == 'Z'))
        return false;
#endif

    return true;
}