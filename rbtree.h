#ifndef RBTREE_H
#define RBTREE_H

#include <stdbool.h>
#include "alloc.h"

#define RBTREE_FOREACH(m, n) \
    for ((n) = rbtree_first(m); (n); (n) = rbtree_next(m, (n)))

typedef struct rbtree_node rbtree_node_t;
typedef struct rbtree rbtree_t;
typedef void (*rbtree_deallocate)(void *);

/*
 * The tree is sorted according to the comparison function rbtree_compare, which
 * must return an integer less than, equal to, or greater than zero if the first
 * argument is considered to be respectively less than, equal to, or greater
 * than the second.
 */
typedef int (*rbtree_compare)(const void *, const void *);

/*
 * Initializes rbtree.
 *
 * Allocates resources for rbtree that needs to be freed with rbtree_free. If
 * allocator is specified this will be used to allocate/deallocate memory for
 * rbtree, else the default allocator is used.
 */
rbtree_t *rbtree_init(rbtree_compare fn, allocator_t *allocator);

/*
 * Inserts element in the tree as long as it doesn't already have an element with
 * an equivalent key.
 */
void rbtree_insert(rbtree_t *tree, void *key, void *data);

/* Removes element with the specific key. */
void rbtree_remove(rbtree_t *tree, void *key);

/* Returns the first element in the tree */
const rbtree_node_t *rbtree_first(rbtree_t *tree);

/* Returns the next element in sorted order */
const rbtree_node_t *rbtree_next(rbtree_t *tree, const rbtree_node_t *node);

/* Returns the key for the specified node */
void *rbtree_get_key(const rbtree_node_t *node);

/* Returns the data for the specified node */
void *rbtree_get_data(const rbtree_node_t *node);

/* Returns the data associated with the specific key */
void *rbtree_data(rbtree_t *tree, void *key);

/* Does rbtree have an element with the specified key? */
bool rbtree_contains(rbtree_t *tree, void *key);

/* Get the number of elements in the tree */
int rbtree_size(rbtree_t *tree);

/* Clear the content of the tree */
void rbtree_clear(rbtree_t *tree);

/* Frees all memory used by rbtree */
void rbtree_free(rbtree_t *tree);

/*
 * If the key should be deallocated, this sets the function that will free the
 * key. The key will be freed on removal and when calling rbtree_free.
 */
void rbtree_set_free_key(rbtree_t *tree, rbtree_deallocate fn);

/*
 * If the data should be deallocated, this sets the function that will free the
 * data. The data will be freed on removal and when calling rbtree_free.
 */
void rbtree_set_free_data(rbtree_t *tree, rbtree_deallocate fn);

#endif
