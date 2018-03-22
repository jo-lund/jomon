#ifndef ALLOC_H
#define ALLOC_H

/* Initializes the memory pools */
void mempool_init();

/* Allocates memory for long-lived storage */
void *mempool_pealloc(int size);

/* Deallocates all memory in the long-lived pool */
void mempool_pefree();

void *mempool_pecopy(void *addr, int size);
void *mempool_pecopy0(void *addr, int size);

/* Allocates memory for short-lived storage */
void *mempool_shalloc(int size);

/*
 * Deallocates ptr and everything allocated in the pool more recently than ptr.
 * To deallocate the whole pool use NULL as argument.
 */
void mempool_shfree(void *ptr);

/* Deallocates the memory pools */
void mempool_free();

#endif
