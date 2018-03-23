#ifndef ALLOC_H
#define ALLOC_H

/* Initializes the memory pools */
void mempool_init();

/* Allocates memory for long-lived storage */
void *mempool_pealloc(int size);

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

/* Allocates memory for short-lived storage */
void *mempool_shalloc(int size);

/*
 * Deallocates ptr and everything allocated in the short-lived pool more recently
 * than ptr. To deallocate the whole pool use NULL as argument.
 */
void mempool_shfree(void *ptr);

/* Deallocates the memory pools */
void mempool_free();

#endif
