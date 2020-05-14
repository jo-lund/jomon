#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include "debug_file.h"
#include "misc.h"
#include "util.h"

#define DEBUG_FILE "/tmp/monitor.log"

static FILE *fp;

bool debug_init()
{
#ifdef MONITOR_DEBUG
    if ((fp = fopen(DEBUG_FILE, "a")) == NULL)
        return false;
    return true;
#else
    return false;
#endif
}

void debug_free()
{
#ifdef MONITOR_DEBUG
    fclose(fp);
#endif
}

bool debug_output(char *file, int line, char *fmt, ...)
{
#ifdef MONITOR_DEBUG
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
    return false;
}
