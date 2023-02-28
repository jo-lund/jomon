#ifndef WRAPPER_H
#define WRAPPER_H

#include <string.h>
#include "error.h"

static inline void *xmalloc(size_t size)
{
    void *p;

    if ((p = malloc(size)) == NULL)
        err_sys("Cannot allocate memory (%lu bytes)", size);
    return p;
}

static inline void *xcalloc(size_t nmemb, size_t size)
{
    void *p;

    if ((p = calloc(nmemb, size)) == NULL)
        err_sys("Cannot allocate memory (%lu bytes)", nmemb * size);
    return p;
}

static inline void *xrealloc(void *p, size_t size)
{
    void *q;

    if ((q = realloc(p, size)) == NULL)
        err_sys("Cannot allocate memory (%lu bytes)", size);
    return q;
}

static inline char *xstrdup(const char *s)
{
    char *p;

    if ((p = strdup(s)) == NULL)
        err_sys("strdup alloc error");
    return p;
}

#endif
