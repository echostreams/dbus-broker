/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "escape.h"
#include "hexdecoct.h"
#include "macro.h"
#include "strv.h"
#include "utf8.h"



int cescape_char(char c, char* buf) {
    char* buf_old = buf;

    /* Needs space for 4 characters in the buffer */

    switch (c) {

    case '\a':
        *(buf++) = '\\';
        *(buf++) = 'a';
        break;
    case '\b':
        *(buf++) = '\\';
        *(buf++) = 'b';
        break;
    case '\f':
        *(buf++) = '\\';
        *(buf++) = 'f';
        break;
    case '\n':
        *(buf++) = '\\';
        *(buf++) = 'n';
        break;
    case '\r':
        *(buf++) = '\\';
        *(buf++) = 'r';
        break;
    case '\t':
        *(buf++) = '\\';
        *(buf++) = 't';
        break;
    case '\v':
        *(buf++) = '\\';
        *(buf++) = 'v';
        break;
    case '\\':
        *(buf++) = '\\';
        *(buf++) = '\\';
        break;
    case '"':
        *(buf++) = '\\';
        *(buf++) = '"';
        break;
    case '\'':
        *(buf++) = '\\';
        *(buf++) = '\'';
        break;

    default:
        /* For special chars we prefer octal over
         * hexadecimal encoding, simply because glib's
         * g_strescape() does the same */
        if ((c < ' ') || (c >= 127)) {
            *(buf++) = '\\';
            *(buf++) = octchar((unsigned char)c >> 6);
            *(buf++) = octchar((unsigned char)c >> 3);
            *(buf++) = octchar((unsigned char)c);
        }
        else
            *(buf++) = c;
        break;
    }

    return (int)(buf - buf_old);
}

char* cescape_length(const char* s, size_t n) {
    const char* f;
    char* r, * t;

    assert(s || n == 0);

    /* Does C style string escaping. May be reversed with
     * cunescape(). */

    r = new(char, n * 4 + 1);
    if (!r)
        return NULL;

    for (f = s, t = r; f < s + n; f++)
        t += cescape_char(*f, t);

    *t = 0;

    return r;
}

char* cescape(const char* s) {
    assert(s);

    return cescape_length(s, strlen(s));
}

int cunescape_one(const char* p, size_t length, char32_t* ret, bool* eight_bit, bool accept_nul) {
    int r = 1;

    assert(p);
    assert(ret);

    /* Unescapes C style. Returns the unescaped character in ret.
     * Sets *eight_bit to true if the escaped sequence either fits in
     * one byte in UTF-8 or is a non-unicode literal byte and should
     * instead be copied directly.
     */

    if (length != SIZE_MAX && length < 1)
        return -EINVAL;

    switch (p[0]) {

    case 'a':
        *ret = '\a';
        break;
    case 'b':
        *ret = '\b';
        break;
    case 'f':
        *ret = '\f';
        break;
    case 'n':
        *ret = '\n';
        break;
    case 'r':
        *ret = '\r';
        break;
    case 't':
        *ret = '\t';
        break;
    case 'v':
        *ret = '\v';
        break;
    case '\\':
        *ret = '\\';
        break;
    case '"':
        *ret = '"';
        break;
    case '\'':
        *ret = '\'';
        break;

    case 's':
        /* This is an extension of the XDG syntax files */
        *ret = ' ';
        break;

    case 'x': {
        /* hexadecimal encoding */
        int a, b;

        if (length != SIZE_MAX && length < 3)
            return -EINVAL;

        a = unhexchar(p[1]);
        if (a < 0)
            return -EINVAL;

        b = unhexchar(p[2]);
        if (b < 0)
            return -EINVAL;

        /* Don't allow NUL bytes */
        if (a == 0 && b == 0 && !accept_nul)
            return -EINVAL;

        *ret = (a << 4U) | b;
        *eight_bit = true;
        r = 3;
        break;
    }

    case 'u': {
        /* C++11 style 16bit unicode */

        int a[4];
        size_t i;
        uint32_t c;

        if (length != SIZE_MAX && length < 5)
            return -EINVAL;

        for (i = 0; i < 4; i++) {
            a[i] = unhexchar(p[1 + i]);
            if (a[i] < 0)
                return a[i];
        }

        c = ((uint32_t)a[0] << 12U) | ((uint32_t)a[1] << 8U) | ((uint32_t)a[2] << 4U) | (uint32_t)a[3];

        /* Don't allow 0 chars */
        if (c == 0 && !accept_nul)
            return -EINVAL;

        *ret = c;
        r = 5;
        break;
    }

    case 'U': {
        /* C++11 style 32bit unicode */

        int a[8];
        size_t i;
        char32_t c;

        if (length != SIZE_MAX && length < 9)
            return -EINVAL;

        for (i = 0; i < 8; i++) {
            a[i] = unhexchar(p[1 + i]);
            if (a[i] < 0)
                return a[i];
        }

        c = ((uint32_t)a[0] << 28U) | ((uint32_t)a[1] << 24U) | ((uint32_t)a[2] << 20U) | ((uint32_t)a[3] << 16U) |
            ((uint32_t)a[4] << 12U) | ((uint32_t)a[5] << 8U) | ((uint32_t)a[6] << 4U) | (uint32_t)a[7];

        /* Don't allow 0 chars */
        if (c == 0 && !accept_nul)
            return -EINVAL;

        /* Don't allow invalid code points */
        if (!unichar_is_valid(c))
            return -EINVAL;

        *ret = c;
        r = 9;
        break;
    }

    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7': {
        /* octal encoding */
        int a, b, c;
        char32_t m;

        if (length != SIZE_MAX && length < 3)
            return -EINVAL;

        a = unoctchar(p[0]);
        if (a < 0)
            return -EINVAL;

        b = unoctchar(p[1]);
        if (b < 0)
            return -EINVAL;

        c = unoctchar(p[2]);
        if (c < 0)
            return -EINVAL;

        /* don't allow NUL bytes */
        if (a == 0 && b == 0 && c == 0 && !accept_nul)
            return -EINVAL;

        /* Don't allow bytes above 255 */
        m = ((uint32_t)a << 6U) | ((uint32_t)b << 3U) | (uint32_t)c;
        if (m > 255)
            return -EINVAL;

        *ret = m;
        *eight_bit = true;
        r = 3;
        break;
    }

    default:
        return -EINVAL;
    }

    return r;
}