#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include "debug.h"
#include "misc.h"
#include "util.h"

#define DEBUG_FILE "/tmp/jomon.log"

#ifdef MONITOR_DEBUG
static FILE *fp;
#endif

bool debug_init(void)
{
#ifdef MONITOR_DEBUG
    if ((fp = fopen(DEBUG_FILE, "a")) == NULL)
        return false;
    return true;
#else
    return false;
#endif
}

void debug_free(void)
{
#ifdef MONITOR_DEBUG
    if (fp)
        fclose(fp);
#endif
}

bool debug_output(char *file, int line, char *fmt, ...)
{
#ifdef MONITOR_DEBUG
    if (!fp)
        return false;

    va_list ap;
    char buf[MAXLINE];
    struct timeval tv;
    char time[16];

    if (gettimeofday(&tv, NULL) != 0)
        return false;
    format_timeval(&tv, time, 16);
    va_start(ap, fmt);
    vsnprintf(buf, MAXLINE - 1, fmt, ap);
    va_end(ap);
    fprintf(fp, "%-20s %s:%-6d: %s\n", time, file, line, buf);
    fflush(fp);
    return true;
#endif
    (void) file;
    (void) line;
    (void) fmt;
    return false;
}
