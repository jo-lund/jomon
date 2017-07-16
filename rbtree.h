#ifndef RBTREE_H
#define RBTREE_H

typedef struct rbtree rbtree_t;

rbtree_t *rbtree_init();
void rbtree_insert(rbtree_t *tree, int key);
void rbtree_remove(rbtree_t *tree, int key);

#endif
