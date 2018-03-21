#include <obstack.h>
#include <stdlib.h>
#include "alloc.h"

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

static struct obstack *global_pool;  /* pool for long-lived memory */
static struct obstack *request_pool; /* pool for short-lived memory */

void mempool_init()
{
    global_pool = malloc(sizeof(struct obstack));
    request_pool = malloc(sizeof(struct obstack));
    obstack_init(global_pool);
    obstack_init(request_pool);
}

inline void *mempool_pealloc(int size)
{
    return obstack_alloc(global_pool, size);
}

inline void mempool_pefree()
{
    obstack_free(global_pool, NULL);
}

inline void *mempool_shalloc(int size)
{
    return obstack_alloc(request_pool, size);
}

inline void mempool_shfree(void *ptr)
{
    obstack_free(request_pool, ptr);
}

void mempool_free()
{
    free(global_pool);
    free(request_pool);
    obstack_free(global_pool, NULL);
    obstack_free(request_pool, NULL);
}
