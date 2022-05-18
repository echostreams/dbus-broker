#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

#if defined(__linux__)
#include <langinfo.h>
#endif

#include "def.h"
#include "env-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "locale-util.h"
#include "path-util.h"
#include "set.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

/*
bool is_locale_utf8() {
#if defined(__linux__)
    return true;
#else
    return false;
#endif
}
*/

#if defined _WIN32 && !defined __CYGWIN__ && defined _MSC_VER

#define SETLOCALE_NULL_MAX (256+1)

static int
setlocale_null_r(int category, char* buf, size_t bufsize)
{

    /* On native Windows, nowadays, the setlocale() implementation is based
       on _wsetlocale() and uses malloc() for the result.  We are better off
       using _wsetlocale() directly.  */
    const wchar_t* result = _wsetlocale(category, NULL);

    if (result == NULL)
    {
        /* CATEGORY is invalid.  */
        if (bufsize > 0)
            /* Return an empty string in BUF.
               This is a convenience for callers that don't want to write explicit
               code for handling EINVAL.  */
            buf[0] = '\0';
        return EINVAL;
    }
    else
    {
        size_t length = wcslen(result);
        if (length < bufsize)
        {
            size_t i;

            /* Convert wchar_t[] -> char[], assuming plain ASCII.  */
            for (i = 0; i <= length; i++)
                buf[i] = (char)result[i];

            return 0;
        }
        else
        {
            if (bufsize > 0)
            {
                /* Return a truncated result in BUF.
                   This is a convenience for callers that don't want to write
                   explicit code for handling ERANGE.  */
                size_t i;

                /* Convert wchar_t[] -> char[], assuming plain ASCII.  */
                for (i = 0; i < bufsize; i++)
                    buf[i] = (char)result[i];
                buf[bufsize - 1] = '\0';
            }
            return ERANGE;
        }
    }
}

static char*
ctype_codeset(void)
{
    static char result[2 + 10 + 1];
    char buf[2 + 10 + 1];
    char locale[SETLOCALE_NULL_MAX];
    char* codeset;
    size_t codesetlen;

    //if (setlocale_null_r(LC_CTYPE, locale, sizeof(locale)))
    if (setlocale_null_r(LC_ALL, locale, sizeof(locale)))
        locale[0] = '\0';

    codeset = buf;
    codeset[0] = '\0';

    fprintf(stderr, "locale: %s\n", locale);

    if (locale[0])
    {
        /* If the locale name contains an encoding after the dot, return it.  */
        char* dot = strchr(locale, '.');

        if (dot)
        {
            /* Look for the possible @... trailer and remove it, if any.  */
            char* codeset_start = dot + 1;
            char const* modifier = strchr(codeset_start, '@');

            if (!modifier)
                codeset = codeset_start;
            else
            {
                codesetlen = modifier - codeset_start;
                if (codesetlen < sizeof buf)
                {
                    codeset = memcpy(buf, codeset_start, codesetlen);
                    codeset[codesetlen] = '\0';
                }
            }
        }
    }

# if defined _WIN32 && ! defined __CYGWIN__
    /* If setlocale is successful, it returns the number of the
       codepage, as a string.  Otherwise, fall back on Windows API
       GetACP, which returns the locale's codepage as a number (although
       this doesn't change according to what the 'setlocale' call specified).
       Either way, prepend "CP" to make it a valid codeset name.  */
    codesetlen = strlen(codeset);
    if (0 < codesetlen && codesetlen < sizeof buf - 2)
        memmove(buf + 2, codeset, codesetlen + 1);
    else
        sprintf(buf + 2, "%u", GetACP());
    /* For a locale name such as "French_France.65001", in Windows 10,
       setlocale now returns "French_France.utf8" instead.  */
    if (strcmp(buf + 2, "65001") == 0 || strcmp(buf + 2, "utf8") == 0)
        return (char*)"UTF-8";
    else
    {
        memcpy(buf, "CP", 2);
        strcpy(result, buf);
        return result;
    }
# else
    strcpy(result, codeset);
    return result;
#endif
}
#endif


bool is_locale_utf8() {
    const char* set;
    static int cached_answer = -1;

    /* Note that we default to 'true' here, since today UTF8 is
     * pretty much supported everywhere. */

    if (cached_answer >= 0)
        goto out;

#ifdef WIN32
    //set = ctype_codeset();
    UINT cp = GetConsoleOutputCP();
    fprintf(stderr, "GetConsoleOutputCP: %d\n", cp);
    if (cp == CP_UTF8)
        cached_answer = true;
    else
        cached_answer = false;
#else

    /* sets system default locale */
    if (!setlocale(LC_ALL, "")) {
        cached_answer = true;
        goto out;
    }


    set = nl_langinfo(CODESET);


    if (!set) {
        cached_answer = true;
        goto out;
    }

    if (streq(set, "UTF-8")) {
        cached_answer = true;
        goto out;
    }

    /* For LC_CTYPE=="C" return true, because CTYPE is effectively
     * unset and everything can do to UTF-8 nowadays. */
    set = setlocale(LC_CTYPE, NULL);
    if (!set) {
        cached_answer = true;
        goto out;
    }

    /* Check result, but ignore the result if C was set
     * explicitly. */
    cached_answer =
        STR_IN_SET(set, "C", "POSIX") &&
        !getenv("LC_ALL") &&
        !getenv("LC_CTYPE") &&
        !getenv("LANG");
#endif

out:
    return (bool)cached_answer;
}