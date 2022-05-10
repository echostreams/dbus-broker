/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
//#include <linux/falloc.h>
//#include <linux/magic.h>
#include <unistd.h>

#include "alloc-util.h"
//#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "log.h"
#include "macro.h"
#include "missing_fcntl.h"
#include "missing_fs.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "ratelimit.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "tmpfile-util.h"
//#include "umask-util.h"
//#include "user-util.h"
#include "util.h"

#if defined(__linux__)

int readlinkat_malloc(int fd, const char* p, char** ret) {
    size_t l = PATH_MAX;

    assert(p);
    assert(ret);

    for (;;) {
        _cleanup_free_ char* c = NULL;
        ssize_t n;

        c = new(char, l + 1);
        if (!c)
            return -ENOMEM;

        n = readlinkat(fd, p, c, l);
        if (n < 0)
            return -errno;

        if ((size_t)n < l) {
            c[n] = 0;
            *ret = TAKE_PTR(c);
            return 0;
        }

        if (l > (SSIZE_MAX - 1) / 2) /* readlinkat() returns an ssize_t, and we want an extra byte for a
                                  * trailing NUL, hence do an overflow check relative to SSIZE_MAX-1
                                  * here */
            return -EFBIG;

        l *= 2;
    }
}

int readlink_malloc(const char* p, char** ret) {
    return readlinkat_malloc(AT_FDCWD, p, ret);
}

#endif