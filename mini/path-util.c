/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the
 * POSIX version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#include "alloc-util.h"
#include "chase-symlinks.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fs-util.h"
#include "glob-util.h"
#include "log.h"
#include "macro.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"

#ifdef WIN32
#define NAME_MAX         255	/* # chars in a file name */
char* stpcpy(char* dst, const char* src);
char* strchrnul(const char* s, int c);
#endif

static const char* skip_slash_or_dot(const char* p) {
    for (; !isempty(p); p++) {
        if (*p == '/')
            continue;
        if (startswith(p, "./")) {
            p++;
            continue;
        }
        break;
    }
    return p;
}


int path_find_first_component(const char** p, bool accept_dot_dot, const char** ret) {
    const char* q, * first, * end_first, * next;
    size_t len;

    assert(p);

    /* When a path is input, then returns the pointer to the first component and its length, and
     * move the input pointer to the next component or nul. This skips both over any '/'
     * immediately *before* and *after* the first component before returning.
     *
     * Examples
     *   Input:  p: "//.//aaa///bbbbb/cc"
     *   Output: p: "bbbbb///cc"
     *           ret: "aaa///bbbbb/cc"
     *           return value: 3 (== strlen("aaa"))
     *
     *   Input:  p: "aaa//"
     *   Output: p: (pointer to NUL)
     *           ret: "aaa//"
     *           return value: 3 (== strlen("aaa"))
     *
     *   Input:  p: "/", ".", ""
     *   Output: p: (pointer to NUL)
     *           ret: NULL
     *           return value: 0
     *
     *   Input:  p: NULL
     *   Output: p: NULL
     *           ret: NULL
     *           return value: 0
     *
     *   Input:  p: "(too long component)"
     *   Output: return value: -EINVAL
     *
     *   (when accept_dot_dot is false)
     *   Input:  p: "//..//aaa///bbbbb/cc"
     *   Output: return value: -EINVAL
     */

    q = *p;

    first = skip_slash_or_dot(q);
    if (isempty(first)) {
        *p = first;
        if (ret)
            *ret = NULL;
        return 0;
    }
    if (streq(first, ".")) {
        *p = first + 1;
        if (ret)
            *ret = NULL;
        return 0;
    }

    end_first = strchrnul(first, '/');
    len = end_first - first;

    if (len > NAME_MAX)
        return -EINVAL;
    if (!accept_dot_dot && len == 2 && first[0] == '.' && first[1] == '.')
        return -EINVAL;

    next = skip_slash_or_dot(end_first);

    *p = next + streq(next, ".");
    if (ret)
        *ret = first;
    return (int)len;
}

char* path_startswith_full(const char* path, const char* prefix, bool accept_dot_dot) {
    assert(path);
    assert(prefix);

    /* Returns a pointer to the start of the first component after the parts matched by
     * the prefix, iff
     * - both paths are absolute or both paths are relative,
     * and
     * - each component in prefix in turn matches a component in path at the same position.
     * An empty string will be returned when the prefix and path are equivalent.
     *
     * Returns NULL otherwise.
     */

    if ((path[0] == '/') != (prefix[0] == '/'))
        return NULL;

    for (;;) {
        const char* p, * q;
        int r, k;

        r = path_find_first_component(&path, accept_dot_dot, &p);
        if (r < 0)
            return NULL;

        k = path_find_first_component(&prefix, accept_dot_dot, &q);
        if (k < 0)
            return NULL;

        if (k == 0)
            return (char*)(p ? p : path);

        if (r != k)
            return NULL;

        if (!strneq(p, q, r))
            return NULL;
    }
}

int path_compare(const char* a, const char* b) {
    int r;

    /* Order NULL before non-NULL */
    r = CMP(!!a, !!b);
    if (r != 0)
        return r;

    /* A relative path and an absolute path must not compare as equal.
     * Which one is sorted before the other does not really matter.
     * Here a relative path is ordered before an absolute path. */
    r = CMP(path_is_absolute(a), path_is_absolute(b));
    if (r != 0)
        return r;

    for (;;) {
        const char* aa, * bb;
        int j, k;

        j = path_find_first_component(&a, true, &aa);
        k = path_find_first_component(&b, true, &bb);

        if (j < 0 || k < 0) {
            /* When one of paths is invalid, order invalid path after valid one. */
            r = CMP(j < 0, k < 0);
            if (r != 0)
                return r;

            /* fallback to use strcmp() if both paths are invalid. */
            return strcmp(a, b);
        }

        /* Order prefixes first: "/foo" before "/foo/bar" */
        if (j == 0) {
            if (k == 0)
                return 0;
            return -1;
        }
        if (k == 0)
            return 1;

        /* Alphabetical sort: "/foo/aaa" before "/foo/b" */
        r = memcmp(aa, bb, MIN(j, k));
        if (r != 0)
            return r;

        /* Sort "/foo/a" before "/foo/aaa" */
        r = CMP(j, k);
        if (r != 0)
            return r;
    }
}

char* path_extend_internal(char** x, ...) {
    size_t sz, old_sz;
    char* q, * nx;
    const char* p;
    va_list ap;
    bool slash;

    /* Joins all listed strings until the sentinel and places a "/" between them unless the strings end/begin
     * already with one so that it is unnecessary. Note that slashes which are already duplicate won't be
     * removed. The string returned is hence always equal to or longer than the sum of the lengths of each
     * individual string.
     *
     * The first argument may be an already allocated string that is extended via realloc() if
     * non-NULL. path_extend() and path_join() are macro wrappers around this function, making use of the
     * first parameter to distinguish the two operations.
     *
     * Note: any listed empty string is simply skipped. This can be useful for concatenating strings of which some
     * are optional.
     *
     * Examples:
     *
     * path_join("foo", "bar") → "foo/bar"
     * path_join("foo/", "bar") → "foo/bar"
     * path_join("", "foo", "", "bar", "") → "foo/bar" */

    sz = old_sz = x ? strlen_ptr(*x) : 0;
    va_start(ap, x);
    while ((p = va_arg(ap, char*)) != POINTER_MAX) {
        size_t add;

        if (isempty(p))
            continue;

        add = 1 + strlen(p);
        if (sz > SIZE_MAX - add) { /* overflow check */
            va_end(ap);
            return NULL;
        }

        sz += add;
    }
    va_end(ap);

    nx = realloc(x ? *x : NULL, GREEDY_ALLOC_ROUND_UP(sz + 1));
    if (!nx)
        return NULL;
    if (x)
        *x = nx;

    if (old_sz > 0)
        slash = nx[old_sz - 1] == '/';
    else {
        nx[old_sz] = 0;
        slash = true; /* no need to generate a slash anymore */
    }

    q = nx + old_sz;

    va_start(ap, x);
    while ((p = va_arg(ap, char*)) != POINTER_MAX) {
        if (isempty(p))
            continue;

        if (!slash && p[0] != '/')
            *(q++) = '/';

        q = stpcpy(q, p);
        slash = endswith(p, "/");
    }
    va_end(ap);

    return nx;
}