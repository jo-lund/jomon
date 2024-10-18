#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <string.h>

#define mempool_calloc(nmemb, type)                     \
    ({                                                  \
        type *t = mempool_alloc((nmemb) * sizeof(*t));  \
        memset(t, 0, (nmemb) * sizeof(*t));             \
    })

enum pool {
    POOL_PERM,  /* pool for long-lived memory */
    POOL_SHORT  /* pool for temporary/short-lived memory */
};

/* Initializes the memory pools. The default pool is POOL_PERM */
void mempool_init(void);

/* Deallocates the memory pools */
void mempool_destruct(void);

/* Allocates memory for stack pool storage. The block will be uninitialized. */
void *mempool_alloc(size_t size);

/*
 * Deallocates ptr and everything allocated in the pool more recently
 * than ptr. To deallocate the whole pool use NULL as argument.
 */
void mempool_free(void *ptr);

/*
 * Set the pool to use. Need to call mempool_set with the previous pool when you
 * are done with the pool, or use MEMPOOL_RELEASE.
 *
 * Returns the old pool
 */
enum pool mempool_set(enum pool p);

/* Frees all memory from the current pool and restores the old */
static inline void mempool_release(void *p)
{
    mempool_free(NULL);
    mempool_set(* (enum pool *) p);
}

/*
 * Automatic cleanup of the current pool. Used as an attribute to the pool
 * returned by mempool_set and will call mempool_release when the variable goes
 * out of scope
 */
#define MEMPOOL_RELEASE __attribute__((cleanup(mempool_release)))

/*
 * Allocates an object in the pool of 'size' bytes with contents
 * copied from address.
 */
void *mempool_copy(void *addr, int size);

/*
 * Allocates an object in the pool of 'size + 1' bytes with 'size'
 * bytes copied from address followed by a null character at the end.
 */
void *mempool_copy0(void *addr, int size);

/*
 * Grow an object sequentially by adding 'size' bytes to the object and copying
 * the contents from data. Using this you don't need to know how much data will
 * be put into the object until you come to the end of it.
 *
 * It is necessay to explicitly say when an object is finished by calling
 * mempool_finish.
 */
void mempool_grow(void *data, int size);

/*
 * Finish growing the object and return the address of the allocated object.
 * Once the object is finished, the pool is available for ordinary allocation or
 * for growing another object.
 */
void *mempool_finish(void);

#endif
