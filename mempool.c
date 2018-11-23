#include <obstack.h>
#include <stdlib.h>
#include "mempool.h"

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#define CHUNK_SIZE 16 * 1024

static struct obstack global_pool;  /* pool for long-lived memory */
static struct obstack request_pool; /* pool for short-lived memory */

/* When the argument to obstack_free is a NULL pointer, the result is an
   uninitialized obstack. globptr will be a pointer to a first dummy object on
   the obstack, and this is used as an argument to obstack_free in order to free
   all memory in the obstack and keep it valid for further allocations. */
static int *globptr;

void mempool_init()
{
    obstack_init(&global_pool);
    obstack_init(&request_pool);
    obstack_chunk_size(&global_pool) = CHUNK_SIZE;
    globptr = obstack_alloc(&global_pool, sizeof(int));
}

void *mempool_pealloc(int size)
{
    return obstack_alloc(&global_pool, size);
}

void mempool_pefree(void *ptr)
{
    if (ptr) {
        obstack_free(&global_pool, ptr);
    } else {
        obstack_free(&global_pool, globptr);
        globptr = obstack_alloc(&global_pool, sizeof(int));
    }
}

void *mempool_pecopy(void *addr, int size)
{
    return obstack_copy(&global_pool, addr, size);
}

void *mempool_pecopy0(void *addr, int size)
{
    return obstack_copy0(&global_pool, addr, size);
}

void mempool_pegrow(void *data, int size)
{
    obstack_grow(&global_pool, data, size);
}

void *mempool_pefinish()
{
    return obstack_finish(&global_pool);
}

void *mempool_shalloc(int size)
{
    return obstack_alloc(&request_pool, size);
}

void mempool_shfree(void *ptr)
{
    obstack_free(&request_pool, ptr);
}

void mempool_free()
{
    obstack_free(&global_pool, NULL);
    obstack_free(&request_pool, NULL);
}
