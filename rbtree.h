#ifndef RBTREE_H
#define RBTREE_H

typedef struct rbtree_node rbtree_node_t;
typedef struct rbtree rbtree_t;
typedef int (*rbtree_compare)(const void *, const void *);
typedef void (*rbtree_deallocate)(void *);

rbtree_t *rbtree_init();
void rbtree_insert(rbtree_t *tree, void *key, void *data, rbtree_compare fn);
void rbtree_remove(rbtree_t *tree, void *key, rbtree_compare fn);
const rbtree_node_t *rbtree_first(rbtree_t *tree);
const rbtree_node_t *rbtree_next(rbtree_t *tree, const rbtree_node_t *node);
void *rbtree_get_key(const rbtree_node_t *node);
void *rbtree_get_data(const rbtree_node_t *node);
void rbtree_free(rbtree_t *tree);
void rbtree_set_free_key(rbtree_t *tree, rbtree_deallocate fn);
void rbtree_set_free_data(rbtree_t *tree, rbtree_deallocate fn);

#endif
