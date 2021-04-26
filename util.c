#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include "util.h"
#include "vector.h"
#include "error.h"
#include "decoder/decoder.h"
#include "debug.h"

#define UUID_LEN 36

/*
 * Transform a hex string in the format aa:bb:cc:dd:ee:ff to its integer
 * representation stored in a char array of size 6.
 */
bool hextoint(unsigned char dest[], char *src)
{
    if (strlen(src) != HW_ADDRSTRLEN) return false;

    uint8_t res;
    char *end;
    int i = 0;

    do {
        errno = 0;
        res = strtoul(src, &end, 16);
        if ((errno != 0 && res == 0) || (i < 5 && *end != ':')) {
            return false;
        }
        dest[i++] = res;
        src += 3;
    } while (*end != '\0' && i < 6);

    return true;
}

void gethost(uint32_t addr, char *host, int hostlen)
{
    struct sockaddr_in saddr;

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = addr;
    getnameinfo((struct sockaddr *) &saddr, sizeof(struct sockaddr_in),
                host, hostlen, NULL, 0, 0);
}

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

char *strtolower(char *str)
{
    char *ptr = str;

    while (*ptr != '\0') {
        *ptr = tolower(*ptr);
        ptr++;
    }
    return str;
}

int str_find_last(const char *str, int c)
{
    int len = strlen(str);

    for (int i = len; i >= 0; i--) {
        if (str[i] == c) {
            return i;
        }
    }
    return -1;
}

char *format_timeval(struct timeval *t, char *buf, int n)
{
    struct tm *time;

    time = localtime(&t->tv_sec);
    strftime(buf, n, "%T", time);
    snprintcat(buf, n, ".%ld", t->tv_usec);
    return buf;
}

char *format_timespec(struct timespec *t, char *buf, int n)
{
    struct tm *time;

    time = localtime(&t->tv_sec);
    strftime(buf, n - 1, "%T", time);
    return buf;
}

char *get_time_from_ms_ut(uint32_t ms, char *buf, int n)
{
    div_t val;
    int hours, mins, secs, msecs;

    val = div(ms, 60 * 60 * 1000);
    hours = val.quot;
    val = div(val.rem, 60 * 1000);
    mins = val.quot;
    val = div(val.rem, 1000);
    secs = val.quot;
    msecs = val.rem;
    snprintf(buf, n, "%02d:%02d:%02d.%03d", hours, mins, secs, msecs);
    return buf;
}

// TODO: Clean this up
struct tm_t get_time(uint32_t num_secs)
{
    struct tm_t t;

    t.days = num_secs / (60 * 60 * 24);
    num_secs %= (60 * 60 * 24);
    t.hours = num_secs / (60 * 60);
    num_secs %= (60 * 60);
    t.mins = num_secs / 60;
    t.secs = num_secs % 60;
    return t;
}

void time_ntop(struct tm_t *time, char *result, int len)
{
    int n = 0;

    memset(result, 0, len);
    if (time->days) {
        n += snprintcat(result, len, time->days == 1 ? "%d day, " : "%d days, ",
                       time->days);
    }
    if (time->hours) {
        n += snprintcat(result, len, time->hours == 1 ? "%d hour, " : "%d hours, ",
                        time->hours);
    }
    if (time->mins) {
        n += snprintcat(result, len, time->mins == 1 ? "%d minute, " :
                        "%d minutes, ", time->mins);
    }
    if (time->secs) {
        n += snprintcat(result, len, time->secs == 1 ? "%d second" :
                        "%d seconds", time->secs);
    }
    if (!n) {
        snprintcat(result, len, "0 seconds");
    } else if (!time->secs) {
        result[n-2] = '\0'; /* remove trailing comma */
    }
}

char *get_directory_part(char *path)
{
    int i;

    i = str_find_last(path, '/');
    if (i == 0) {
        path[i + 1] = '\0';
    } else if (i != -1) {
        path[i] = '\0';
    }
    return path;
}

char *get_file_part(char *path)
{
    int i;

    i = str_find_last(path, '/');
    if (i != -1) {
        int n;

        n = strlen(path + i + 1);
        memmove(path, path + i + 1, n);
        path[n] = '\0';
    }
    return path;
}

char *format_bytes(int bytes, char *buf, int len)
{
    static const char *format[] = { "", "K", "M", "G", "T" };
    float f = bytes;
    unsigned int c = 0;

    while (f > 1024) {
        f /= 1024.0;
        c++;
    }
    if (c < sizeof(format) / sizeof(const char *)) {
        float decpt = f - (int) f;

        if (decpt >= 0.1) {
            snprintf(buf, len, "%.1f%s", f, format[c]);
        } else {
            snprintf(buf, len, "%d%s", (int) f, format[c]);
        }
    }
    return buf;
}

/* Clean this up! */
char *uuid_format(uint8_t *uuid)
{
    char *str;
    char *p;
    int len;

    if (uuid == NULL)
        return NULL;
    len = UUID_LEN + 1;
    str = malloc(len);
    p = str;
    for (int i = 0; i < 4; i++) {
        snprintf(p, len, "%02x", *uuid++);
        p += 2;
        len -= 2;
    }
    *p++ = '-';
    len--;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 2; j++) {
            snprintf(p, len, "%02x", *uuid++);
            p += 2;
            len -= 2;
        }
        *p++ = '-';
        len--;
    }
    for (int i = 0; i < 6; i++) {
        snprintf(p, len, "%02x", *uuid++);
        p += 2;
        len -= 2;
    }
    return str;
}
