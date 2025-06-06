#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "error.h"
#include "jomon.h"

/* Print error message to standard error */
static void print_error(const char *fmt, int error, va_list ap)
{
    char buf[MAXLINE];

    vsnprintf(buf, MAXLINE - 1, fmt, ap);
    if (error) {
        snprintf(buf + strlen(buf), MAXLINE - strlen(buf), ": %s",
                 strerror(error));
    }
    strcat(buf, "\n");
    fputs(buf, stderr);
}

void err_sys(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    print_error(fmt, errno, ap);
    va_end(ap);
    jomon_exit(1);
}

void err_quit(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    print_error(fmt, 0, ap);
    va_end(ap);
    jomon_exit(1);
}

void err_msg(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    print_error(fmt, errno, ap);
    va_end(ap);
}
