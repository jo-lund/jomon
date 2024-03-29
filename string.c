#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include "string.h"
#include "debug.h"

int snprintcat(char *buf, int size, char *fmt, ...)
{
    va_list ap;
    int len;
    int n;

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
        *ptr = tolower(*ptr);
        ptr++;
    }
    return str;
}

int string_find_last(const char *str, int c)
{
    int len = strlen(str);

    for (int i = len; i >= 0; i--) {
        if (str[i] == c) {
            return i;
        }
    }
    return -1;
}

void string_truncate(char *str, size_t len, size_t max)
{
    size_t n;

    if (len <= max || len < 3 || max < 3)
        return;
    n = max - 3;
    strlcpy(str + n, "...", len - n);
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
