#ifndef DEBUG_H
#define DEBUG_H

#include <stdbool.h>

#define DEBUG_FATAL
#define DEBUG_ERROR
#define DEBUG_WARNING
#define DEBUG_INFO

#ifdef MONITOR_DEBUG
#define DEBUG(fmt, ...) debug_output(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define DEBUG(fmt, ...)
#endif

bool debug_init(void);
void debug_free(void);
bool debug_output(char *file, int line, char *fmt, ...);

#endif
