#ifndef ALLOC_H
#define ALLOC_H

#include <stdlib.h>

typedef void *(*alloc_fn)(size_t);
typedef void (*dealloc_fn)(void *);

typedef struct allocator {
    alloc_fn alloc;
    dealloc_fn dealloc;
} allocator_t;

/* Initialize the default allocator */
static inline void allocator_init(allocator_t *allocator)
{
    allocator->alloc = malloc;
    allocator->dealloc = free;
}

#endif
