#include <obstack.h>
#include <stdlib.h>
#include "mempool.h"

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#define CHUNK_SIZE 16 * 1024

#define NUM_POOLS 2

struct mempool {
    struct obstack pool;

    /* When the argument to obstack_free is a NULL pointer, the result is an
       uninitialized obstack. obj will be a pointer to a first dummy object on
       the obstack, and this is used as an argument to obstack_free in order to free
       all memory in the obstack and keep it valid for further allocations. */
    int *obj;
};

static struct mempool mempool[NUM_POOLS];
static enum pool mempool_store = POOL_PERM;

void mempool_init(void)
{
    /* POOL_SHORT will use the default chunk size of 4096 bytes */
    for (int i = 0; i < NUM_POOLS; i++) {
        obstack_init(&mempool[i].pool);
        mempool[i].obj = obstack_alloc(&mempool[i].pool, sizeof(int));
    }
    obstack_chunk_size(&mempool[POOL_PERM].pool) = CHUNK_SIZE;
}

void mempool_destruct(void)
{
    for (int i = 0; i < NUM_POOLS; i++)
        obstack_free(&mempool[i].pool, NULL);
}

enum pool mempool_set(enum pool p)
{
	enum pool prev = mempool_store;

    mempool_store = p;
	return prev;
}

void *mempool_alloc(size_t size)
{
    return obstack_alloc(&mempool[mempool_store].pool, size);
}

void mempool_free(void *ptr)
{
    if (ptr) {
        obstack_free(&mempool[mempool_store].pool, ptr);
    } else {
        obstack_free(&mempool[mempool_store].pool, mempool[mempool_store].obj);
        mempool[mempool_store].obj = obstack_alloc(&mempool[mempool_store].pool, sizeof(int));
    }
}

void *mempool_copy(void *addr, int size)
{
    return obstack_copy(&mempool[mempool_store].pool, addr, size);
}

void *mempool_copy0(void *addr, int size)
{
    return obstack_copy0(&mempool[mempool_store].pool, addr, size);
}

void mempool_grow(void *data, int size)
{
    obstack_grow(&mempool[mempool_store].pool, data, size);
}

void *mempool_finish(void)
{
    return obstack_finish(&mempool[mempool_store].pool);
}
