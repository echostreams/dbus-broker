/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <utmp.h>
#endif

#include "sd-messages.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "path-util.h"
#include "random-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "utf8.h"

bool uid_is_valid(uid_t uid) {

    /* Also see POSIX IEEE Std 1003.1-2008, 2016 Edition, 3.436. */

    /* Some libc APIs use UID_INVALID as special placeholder */
    if (uid == (uid_t)UINT32_C(0xFFFFFFFF))
        return false;

    /* A long time ago UIDs where 16bit, hence explicitly avoid the 16bit -1 too */
    if (uid == (uid_t)UINT32_C(0xFFFF))
        return false;

    return true;
}


int parse_uid(const char* s, uid_t* ret) {
    uint32_t uid = 0;
    int r;

    assert(s);

    assert_cc(sizeof(uid_t) == sizeof(uint32_t));

    /* We are very strict when parsing UIDs, and prohibit +/- as prefix, leading zero as prefix, and
     * whitespace. We do this, since this call is often used in a context where we parse things as UID
     * first, and if that doesn't work we fall back to NSS. Thus we really want to make sure that UIDs
     * are parsed as UIDs only if they really really look like UIDs. */
    r = safe_atou32_full(s, 10
        | SAFE_ATO_REFUSE_PLUS_MINUS
        | SAFE_ATO_REFUSE_LEADING_ZERO
        | SAFE_ATO_REFUSE_LEADING_WHITESPACE, &uid);
    if (r < 0)
        return r;

    if (!uid_is_valid(uid))
        return -ENXIO; /* we return ENXIO instead of EINVAL
                        * here, to make it easy to distinguish
                        * invalid numeric uids from invalid
                        * strings. */

    if (ret)
        *ret = uid;

    return 0;
}