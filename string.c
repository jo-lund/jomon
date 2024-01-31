#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include "string.h"
#include "debug.h"

int snprintcat(char *buf, size_t size, char *fmt, ...)
{
    va_list ap;
    size_t len;
    int n;

    assert(size > 0);
    len = strnlen(buf, size);
    va_start(ap, fmt);
    n = vsnprintf(buf + len, size - len, fmt, ap);
    va_end(ap);
    return n;
}

char *string_tolower(char *str)
{
    char *ptr = str;

    while (*ptr != '\0') {
        *ptr = (char) tolower(*ptr);
        ptr++;
    }
    return str;
}

int string_find_last(const char *str, int c)
{
    int len = (int) strlen(str);

    for (int i = len; i >= 0; i--) {
        if (str[i] == c) {
            return i;
        }
    }
    return -1;
}

void string_truncate(char *str, size_t len, size_t max)
{
    if (len <= max || len < 3 || max < 3)
        return;

    size_t n = max - 3;

    strncpy(str + n, "...", len - n);
    str[max] = '\0';
}

char *string_trim_whitespace(char *str)
{
    char *p, *q;

    p = str;
    q = p + strlen(str);
    while (isspace(*p))
        p++;
    while (q > p && isspace(*(q - 1)))
        q--;
    *q = '\0';
    return p;
}
