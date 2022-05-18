/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/time.h>
#else
#include <time.h>
#endif

#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "ratelimit.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "time-util.h"
#include "utf8.h"


ColorMode get_color_mode(void)
{
    return COLOR_OFF;
}

#define SNDBUF_SIZE (8*1024*1024)

#ifdef WIN32
#define LINE_MAX 2048
#endif

static int log_max_level = LOG_INFO;

/* Akin to glibc's __abort_msg; which is private and we hence cannot
 * use here. */
static char* log_abort_msg = NULL;

void log_set_max_level(int level) {
    assert(level == LOG_NULL || (level & LOG_PRIMASK) == level);

    log_max_level = level;
}

int log_get_max_level(void) {
    return log_max_level;
}

int log_dispatch_internal(
    int level,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* object_field,
    const char* object,
    const char* extra_field,
    const char* extra,
    char* buffer) {

    fprintf(stderr, "%s\n", buffer);
    return 0;
   
}

int log_internalv(
    int level,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* format,
    va_list ap) {

    char buffer[LINE_MAX];
    PROTECT_ERRNO;

    if (_likely_(LOG_PRI(level) > log_max_level))
        return -ERRNO_VALUE(error);

    /* Make sure that %m maps to the specified error (or "Success"). */
    errno = ERRNO_VALUE(error);

    (void)vsnprintf(buffer, sizeof buffer, format, ap);

    return log_dispatch_internal(level, error, file, line, func, NULL, NULL, NULL, NULL, buffer);
}

int log_internal(
    int level,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* format, ...) {

    va_list ap;
    int r;

    va_start(ap, format);
    r = log_internalv(level, error, file, line, func, format, ap);
    va_end(ap);

    return r;
}

int log_object_internalv(
    int level,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* object_field,
    const char* object,
    const char* extra_field,
    const char* extra,
    const char* format,
    va_list ap) {

    PROTECT_ERRNO;
    char* buffer, * b;

    if (_likely_(LOG_PRI(level) > log_max_level))
        return -ERRNO_VALUE(error);

    /* Make sure that %m maps to the specified error (or "Success"). */
    errno = ERRNO_VALUE(error);

    /* Prepend the object name before the message */
    if (object) {
        size_t n;

        n = strlen(object);
        //buffer = newa(char, n + 2 + LINE_MAX);
#ifdef WIN32
        buffer = (char*)_alloca(n + 2 + LINE_MAX);
#else
        buffer = alloca(n + 2 + LINE_MAX);
#endif
        b = stpcpy(stpcpy(buffer, object), ": ");
    }
    else
        //b = buffer = newa(char, LINE_MAX);
#ifdef WIN32
        b = buffer = (char*)_alloca(LINE_MAX);
#else
        b = buffer = alloca(LINE_MAX);
#endif

    (void)vsnprintf(b, LINE_MAX, format, ap);

    return log_dispatch_internal(level, error, file, line, func,
        object_field, object, extra_field, extra, buffer);
}

static void log_assert(
    int level,
    const char* text,
    const char* file,
    int line,
    const char* func,
    const char* format) {

    static char buffer[LINE_MAX];

    if (_likely_(LOG_PRI(level) > log_max_level))
        return;

#if defined(__GNUC__)
    DISABLE_WARNING_FORMAT_NONLITERAL;
#endif
    (void)snprintf(buffer, sizeof buffer, format, text, file, line, func);
#if defined(__GNUC__)
    REENABLE_WARNING;
#endif

    log_abort_msg = buffer;

    //log_dispatch_internal(level, 0, file, line, func, NULL, NULL, NULL, NULL, buffer);
    fprintf(stderr, "%s\n", buffer);
}


_noreturn_ void log_assert_failed(
    const char* text,
    const char* file,
    int line,
    const char* func) {
    log_assert(LOG_CRIT, text, file, line, func,
        "Assertion '%s' failed at %s:%u, function %s(). Aborting.");
    abort();
}

_noreturn_ void log_assert_failed_unreachable(
    const char* file,
    int line,
    const char* func) {
    log_assert(LOG_CRIT, "Code should not be reached", file, line, func,
        "%s at %s:%u, function %s(). Aborting.");
    abort();
}

void log_assert_failed_return(
    const char* text,
    const char* file,
    int line,
    const char* func) {
    PROTECT_ERRNO;
    log_assert(LOG_DEBUG, text, file, line, func,
        "Assertion '%s' failed at %s:%u, function %s(). Ignoring.");
}

int log_oom_internal(int level, const char* file, int line, const char* func) {
    return log_internal(level, ENOMEM, file, line, func, "Out of memory.");
}

int log_struct_internal(
    int level,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* format, ...) {

    char buf[LINE_MAX];
    bool found = false;
    PROTECT_ERRNO;
    va_list ap;

    if (_likely_(LOG_PRI(level) > log_max_level) /* ||
        log_target == LOG_TARGET_NULL */)
        return -ERRNO_VALUE(error);

#if 0

    if ((level & LOG_FACMASK) == 0)
        level |= log_facility;


    if (IN_SET(log_target,
        LOG_TARGET_AUTO,
        LOG_TARGET_JOURNAL_OR_KMSG,
        LOG_TARGET_JOURNAL)) {

        if (open_when_needed)
            log_open_journal();

        if (journal_fd >= 0) {
            char header[LINE_MAX];
            struct iovec iovec[17];
            size_t n = 0;
            int r;
            bool fallback = false;

            /* If the journal is available do structured logging.
             * Do not report the errno if it is synthetic. */
            log_do_header(header, sizeof(header), level, error, file, line, func, NULL, NULL, NULL, NULL);
            iovec[n++] = IOVEC_MAKE_STRING(header);

            va_start(ap, format);
            r = log_format_iovec(iovec, ELEMENTSOF(iovec), &n, true, error, format, ap);
            if (r < 0)
                fallback = true;
            else {
                const struct msghdr msghdr = {
                        .msg_iov = iovec,
                        .msg_iovlen = n,
                };

                (void)sendmsg(journal_fd, &msghdr, MSG_NOSIGNAL);
            }

            va_end(ap);
            for (size_t i = 1; i < n; i += 2)
                free(iovec[i].iov_base);

            if (!fallback) {
                if (open_when_needed)
                    log_close();

                return -ERRNO_VALUE(error);
            }
        }
    }
#endif

    /* Fallback if journal logging is not available or didn't work. */

    va_start(ap, format);
    while (format) {
        va_list aq;

        errno = ERRNO_VALUE(error);

        va_copy(aq, ap);
        (void)vsnprintf(buf, sizeof buf, format, aq);
        va_end(aq);

        if (startswith(buf, "MESSAGE=")) {
            found = true;
            break;
        }

        //VA_FORMAT_ADVANCE(format, ap);

        format = va_arg(ap, char*);
    }
    va_end(ap);

    //if (!found) {
    //    if (open_when_needed)
    //        log_close();
    //
    //    return -ERRNO_VALUE(error);
    //}

    return log_dispatch_internal(level, error, file, line, func, NULL, NULL, NULL, NULL, buf + 8);
}

int log_syntax_internal(
    const char* unit,
    int level,
    const char* config_file,
    unsigned config_line,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* format, ...) {

    //if (log_syntax_callback)
    //    log_syntax_callback(unit, level, log_syntax_callback_userdata);

    PROTECT_ERRNO;
    char buffer[LINE_MAX];
    va_list ap;
    const char* unit_fmt = NULL;

    if (_likely_(LOG_PRI(level) > log_max_level) /* ||
        log_target == LOG_TARGET_NULL*/)
        return -ERRNO_VALUE(error);

    errno = ERRNO_VALUE(error);

    va_start(ap, format);
    (void)vsnprintf(buffer, sizeof buffer, format, ap);
    va_end(ap);

    if (unit)
        unit_fmt = getpid_cached() == 1 ? "UNIT=%s" : "USER_UNIT=%s";

    if (config_file) {
        if (config_line > 0)
            return log_struct_internal(
                level,
                error,
                file, line, func,
                "MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR,
                "CONFIG_FILE=%s", config_file,
                "CONFIG_LINE=%u", config_line,
                LOG_MESSAGE("%s:%u: %s", config_file, config_line, buffer),
                unit_fmt, unit,
                NULL);
        else
            return log_struct_internal(
                level,
                error,
                file, line, func,
                "MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR,
                "CONFIG_FILE=%s", config_file,
                LOG_MESSAGE("%s: %s", config_file, buffer),
                unit_fmt, unit,
                NULL);
    }
    else if (unit)
        return log_struct_internal(
            level,
            error,
            file, line, func,
            "MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR,
            LOG_MESSAGE("%s: %s", unit, buffer),
            unit_fmt, unit,
            NULL);
    else
        return log_struct_internal(
            level,
            error,
            file, line, func,
            "MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR,
            LOG_MESSAGE("%s", buffer),
            NULL);
}