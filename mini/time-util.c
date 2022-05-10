#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mman.h>
#if defined(__linux)
#include <sys/time.h>
#include <sys/timerfd.h>
#endif
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "missing_timerfd.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

static clockid_t map_clock_id(clockid_t c) {

    /* Some more exotic archs (s390, ppc, …) lack the "ALARM" flavour of the clocks. Thus, clock_gettime() will
     * fail for them. Since they are essentially the same as their non-ALARM pendants (their only difference is
     * when timers are set on them), let's just map them accordingly. This way, we can get the correct time even on
     * those archs. */

    switch (c) {

    case CLOCK_BOOTTIME_ALARM:
        return CLOCK_BOOTTIME;

    case CLOCK_REALTIME_ALARM:
        return CLOCK_REALTIME;

    default:
        return c;
    }
}

usec_t timespec_load(const struct timespec* ts) {
    assert(ts);

    if (ts->tv_sec < 0 || ts->tv_nsec < 0)
        return USEC_INFINITY;

    if ((usec_t)ts->tv_sec > (UINT64_MAX - (ts->tv_nsec / NSEC_PER_USEC)) / USEC_PER_SEC)
        return USEC_INFINITY;

    return
        (usec_t)ts->tv_sec * USEC_PER_SEC +
        (usec_t)ts->tv_nsec / NSEC_PER_USEC;
}

nsec_t timespec_load_nsec(const struct timespec* ts) {
    assert(ts);

    if (ts->tv_sec < 0 || ts->tv_nsec < 0)
        return NSEC_INFINITY;

    if ((nsec_t)ts->tv_sec >= (UINT64_MAX - ts->tv_nsec) / NSEC_PER_SEC)
        return NSEC_INFINITY;

    return (nsec_t)ts->tv_sec * NSEC_PER_SEC + (nsec_t)ts->tv_nsec;
}


usec_t now(clockid_t clock_id) {
    struct timespec ts;

    assert_se(clock_gettime(map_clock_id(clock_id), &ts) == 0);

    return timespec_load(&ts);
}


nsec_t now_nsec(clockid_t clock_id) {
    struct timespec ts;

    assert_se(clock_gettime(map_clock_id(clock_id), &ts) == 0);

    return timespec_load_nsec(&ts);
}

dual_timestamp* dual_timestamp_get(dual_timestamp* ts) {
    assert(ts);

    ts->realtime = now(CLOCK_REALTIME);
    ts->monotonic = now(CLOCK_MONOTONIC);

    return ts;
}

triple_timestamp* triple_timestamp_get(triple_timestamp* ts) {
    assert(ts);

    ts->realtime = now(CLOCK_REALTIME);
    ts->monotonic = now(CLOCK_MONOTONIC);
    ts->boottime = clock_boottime_supported() ? now(CLOCK_BOOTTIME) : USEC_INFINITY;

    return ts;
}

#ifdef _WIN32
//inline struct tm* localtime_r(const time_t * clock, struct tm* result) {
//    if (!clock || !result) return NULL;
//    memcpy(result, localtime(clock), sizeof(*result));
//    return result;
//}
#define localtime_r(a, b)       (localtime_s(b, a) == 0 ? b : NULL)
#define gmtime_r(a, b)          (gmtime_s(b, a) == 0 ? b : NULL)

#endif

struct tm* localtime_or_gmtime_r(const time_t* t, struct tm* tm, bool utc) {
    return utc ? gmtime_r(t, tm) : localtime_r(t, tm);
}


char* format_timestamp_style(
    char* buf,
    size_t l,
    usec_t t,
    TimestampStyle style) {

    /* The weekdays in non-localized (English) form. We use this instead of the localized form, so that our
     * generated timestamps may be parsed with parse_timestamp(), and always read the same. */
    static const char* const weekdays[] = {
            [0] = "Sun",
            [1] = "Mon",
            [2] = "Tue",
            [3] = "Wed",
            [4] = "Thu",
            [5] = "Fri",
            [6] = "Sat",
    };

    struct tm tm;
    time_t sec;
    size_t n;
    bool utc = false, us = false;

    assert(buf);

    switch (style) {
    case TIMESTAMP_PRETTY:
        break;
    case TIMESTAMP_US:
        us = true;
        break;
    case TIMESTAMP_UTC:
        utc = true;
        break;
    case TIMESTAMP_US_UTC:
        us = true;
        utc = true;
        break;
    default:
        return NULL;
    }

    if (l < (size_t)(3 +                  /* week day */
        1 + 10 +             /* space and date */
        1 + 8 +              /* space and time */
        (us ? 1 + 6 : 0) +   /* "." and microsecond part */
        1 + 1 +              /* space and shortest possible zone */
        1))
        return NULL; /* Not enough space even for the shortest form. */
    if (t <= 0 || t == USEC_INFINITY)
        return NULL; /* Timestamp is unset */

/* Let's not format times with years > 9999 */
    if (t > USEC_TIMESTAMP_FORMATTABLE_MAX) {
        assert(l >= STRLEN("--- XXXX-XX-XX XX:XX:XX") + 1);
        strcpy(buf, "--- XXXX-XX-XX XX:XX:XX");
        return buf;
    }

    sec = (time_t)(t / USEC_PER_SEC); /* Round down */

    if (!localtime_or_gmtime_r(&sec, &tm, utc))
        return NULL;

    /* Start with the week day */
    assert((size_t)tm.tm_wday < ELEMENTSOF(weekdays));
    memcpy(buf, weekdays[tm.tm_wday], 4);

    /* Add the main components */
    if (strftime(buf + 3, l - 3, " %Y-%m-%d %H:%M:%S", &tm) <= 0)
        return NULL; /* Doesn't fit */

/* Append the microseconds part, if that's requested */
    if (us) {
        n = strlen(buf);
        if (n + 8 > l)
            return NULL; /* Microseconds part doesn't fit. */

        sprintf(buf + n, ".%06"PRI_USEC, t % USEC_PER_SEC);
    }

    /* Append the timezone */
    n = strlen(buf);
    if (utc) {
        /* If this is UTC then let's explicitly use the "UTC" string here, because gmtime_r() normally uses the
         * obsolete "GMT" instead. */
        if (n + 5 > l)
            return NULL; /* "UTC" doesn't fit. */

        strcpy(buf + n, " UTC");

    }
#if defined(__linux__)
    else if (!isempty(tm.tm_zone)) {
        size_t tn;

        /* An explicit timezone is specified, let's use it, if it fits */
        tn = strlen(tm.tm_zone);
        if (n + 1 + tn + 1 > l) {
            /* The full time zone does not fit in. Yuck. */

            if (n + 1 + _POSIX_TZNAME_MAX + 1 > l)
                return NULL; /* Not even enough space for the POSIX minimum (of 6)? In that case, complain that it doesn't fit */

        /* So the time zone doesn't fit in fully, but the caller passed enough space for the POSIX
         * minimum time zone length. In this case suppress the timezone entirely, in order not to dump
         * an overly long, hard to read string on the user. This should be safe, because the user will
         * assume the local timezone anyway if none is shown. And so does parse_timestamp(). */
        }
        else {
            buf[n++] = ' ';
            strcpy(buf + n, tm.tm_zone);
        }
    }
#endif
    return buf;
}

struct timespec* timespec_store(struct timespec* ts, usec_t u) {
    assert(ts);

    if (u == USEC_INFINITY ||
        u / USEC_PER_SEC >= TIME_T_MAX) {
        ts->tv_sec = (time_t)-1;
        ts->tv_nsec = -1L;
        return ts;
    }

    ts->tv_sec = (time_t)(u / USEC_PER_SEC);
    ts->tv_nsec = (long)((u % USEC_PER_SEC) * NSEC_PER_USEC);

    return ts;
}

bool clock_boottime_supported(void) {
    static int supported = -1;

    /* Note that this checks whether CLOCK_BOOTTIME is available in general as well as available for timerfds()! */

    if (supported < 0) {
        int fd = -1;
#if defined(__linux__)
        fd = timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK | TFD_CLOEXEC);
#endif
        if (fd < 0)
            supported = false;
        else {
            safe_close(fd);
            supported = true;
        }
    }

    return supported;
}

bool clock_supported(clockid_t clock) {
    struct timespec ts;

    switch (clock) {

    case CLOCK_MONOTONIC:
    case CLOCK_REALTIME:
        return true;

    case CLOCK_BOOTTIME:
        return clock_boottime_supported();

    case CLOCK_BOOTTIME_ALARM:
        if (!clock_boottime_supported())
            return false;

        _fallthrough_;
    default:
        /* For everything else, check properly */
        return clock_gettime(clock, &ts) >= 0;
    }
}