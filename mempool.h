#ifndef MEMPOOL_H
#define MEMPOOL_H

#define MEMPOOL_CALLOC(type, pool)                      \
    ({                                                  \
        type *t = mempool_##pool##alloc(sizeof(*t));    \
        memset(t, 0, sizeof(*t));                       \
    })


/* Initializes the memory pools */
void mempool_init();

/* Allocates memory for long-lived storage. The block will be uninitialized. */
void *mempool_pealloc(size_t size);

/*
 * Deallocates ptr and everything allocated in the long-lived pool more recently
 * than ptr. To deallocate the whole pool use NULL as argument.
 */
void mempool_pefree(void *ptr);

/*
 * Allocates an object in the long-lived pool of 'size' bytes with contents
 * copied from address.
 */
void *mempool_pecopy(void *addr, int size);

/*
 * Allocates an object in the long-lived pool of 'size + 1' bytes with 'size'
 * bytes copied from address followed by a null character at the end.
 */
void *mempool_pecopy0(void *addr, int size);

/*
 * Grow an object sequentially by adding 'size' bytes to the object and copying
 * the contents from data. Using this you don't need to know how much data will
 * be put into the object until you come to the end of it.
 *
 * It is necessay to explicitly say when an object is finished by calling
 * mempool_pefinish.
 */
void mempool_pegrow(void *data, int size);

/*
 * Finish growing the object and return the address of the allocated object.
 * Once the object is finished, the pool is available for ordinary allocation or
 * for growing another object.
 */
void *mempool_pefinish();

/* Allocates memory for short-lived storage. The block will be uninitialized. */
void *mempool_shalloc(size_t size);

/*
 * Allocates an object in the short-lived pool of 'size' bytes with contents
 * copied from address.
 */
void *mempool_shcopy(void *addr, int size);

/*
 * Deallocates ptr and everything allocated in the short-lived pool more recently
 * than ptr. To deallocate the whole pool use NULL as argument.
 */
void mempool_shfree(void *ptr);

/* Deallocates the memory pools */
void mempool_free();

#endif
