#include <stdint.h>
#include <string.h>
#include "rbtree.h"

/*
 * Red-black tree properties:
 * 1. Every node is either red or black.
 * 2. Every leaf (NULL) is black.
 * 3. If a node is red, then both its children are black.
 * 4. Every simple path from a node to a descendant leaf contains the same
 *    number of black nodes.
 * 5. The root is always black
 */

#define RED 0
#define BLACK 1

struct rbtree_node {
    void *key;
    void *data;
    uint8_t colour;
    struct rbtree_node *parent;
    struct rbtree_node *left;
    struct rbtree_node *right;
};

struct rbtree {
    rbtree_node_t *root;
    rbtree_node_t *nil; /* sentinel node */
    rbtree_deallocate free_key;
    rbtree_deallocate free_data;
    rbtree_compare comp;
    allocator_t allocator;
    int size;
};

#define INIT_NODE(n, p, k, d)                   \
    do {                                        \
        (n)->key = k;                           \
        (n)->data = d;                          \
        (n)->colour = RED;                      \
        (n)->parent = p;                        \
        (n)->left = tree->nil;                  \
        (n)->right = tree->nil;                 \
    } while (0)

static rbtree_node_t *insert_node(rbtree_t *tree, void *key, void *data);
static void remove_fixup(rbtree_t *tree, rbtree_node_t *x);
static void left_rotate(rbtree_t *tree, rbtree_node_t *n);
static void right_rotate(rbtree_t *tree, rbtree_node_t *n);
static rbtree_node_t *get_minimum(rbtree_t *tree, rbtree_node_t *n);
static rbtree_node_t *get_successor(rbtree_t *tree, rbtree_node_t *n);
static void free_nodes(rbtree_t *tree, rbtree_node_t *n);

rbtree_t *rbtree_init(rbtree_compare fn, allocator_t *allocator)
{
    rbtree_t *tree;

    if (allocator) {
        tree = allocator->alloc(sizeof(struct rbtree));
        memset(tree, 0, sizeof(struct rbtree));
        tree->allocator.alloc = allocator->alloc;
        tree->allocator.dealloc = allocator->dealloc;
    } else {
        tree = calloc(1, sizeof(struct rbtree));
        allocator_init(&tree->allocator);
    }
    tree->nil = tree->allocator.alloc(sizeof(struct rbtree_node));
    INIT_NODE(tree->nil, NULL, NULL, NULL);
    tree->root = tree->nil;
    tree->nil->colour = BLACK;
    tree->comp = fn;
    tree->size = 0;
    return tree;
}

void rbtree_free(rbtree_t *tree)
{
    free_nodes(tree, tree->root);
    if (tree->allocator.dealloc) {
        tree->allocator.dealloc(tree->nil);
        tree->allocator.dealloc(tree);
    }
}

void rbtree_clear(rbtree_t *tree)
{
    free_nodes(tree, tree->root);
    tree->size = 0;
    tree->root = tree->nil;
}

void rbtree_insert(rbtree_t *tree, void *key, void *data)
{
    if (tree->root == tree->nil) {
        tree->root = tree->allocator.alloc(sizeof(struct rbtree_node));
        INIT_NODE(tree->root, tree->nil, key, data);
    } else {
        rbtree_node_t *x;

        x = insert_node(tree, key, data);
        if (x == tree->nil) return;
        while (x != tree->root && x->parent->colour == RED) {
            if (x->parent == x->parent->parent->left) { /* parent is a left child */
                rbtree_node_t *y = x->parent->parent->right; /* the parent's sibling */

                /* case 1: x's parent and the parent's sibling are both red */
                if (y != tree->nil && y->colour == RED) {
                    x->parent->colour = BLACK;
                    y->colour = BLACK;
                    x->parent->parent->colour = RED;
                    x = x->parent->parent;
                } else {
                    if (x == x->parent->right) {
                        /* case 2: sibling is black and x is a right child */
                        x = x->parent;
                        left_rotate(tree, x);
                    }
                    /* case 3: sibling is black and x is a left child */
                    x->parent->colour = BLACK;
                    x->parent->parent->colour = RED;
                    right_rotate(tree, x->parent->parent);
                }
            } else { /* parent is a right child */
                rbtree_node_t *y = x->parent->parent->left;

                /* case 1: x's parent and the parent's sibling are both red */
                if (y != tree->nil && y->colour == RED) {
                    x->parent->colour = BLACK;
                    y->colour = BLACK;
                    x->parent->parent->colour = RED;
                    x = x->parent->parent;
                } else {
                    if (x == x->parent->left) {
                        /* case 2: sibling is black and x is a left child */
                        x = x->parent;
                        right_rotate(tree, x);
                    }
                    /* case 3: sibling is black and x is a right child */
                    x->parent->colour = BLACK;
                    x->parent->parent->colour = RED;
                    left_rotate(tree, x->parent->parent);
                }
            }
        }
    }
    tree->root->colour = BLACK;
    tree->size++;
}

rbtree_node_t *insert_node(rbtree_t *tree, void *key, void *data)
{
    rbtree_node_t *n = tree->root;

    while (n != tree->nil) {
        if (tree->comp(key, n->key) < 0) {
            if (n->left == tree->nil) {
                rbtree_node_t *x;

                x = tree->allocator.alloc(sizeof(struct rbtree_node));
                INIT_NODE(x, n, key, data);
                n->left = x;
                return x;
            }
            n = n->left;
        } else if (tree->comp(key, n->key) > 0) {
            if (n->right == tree->nil) {
                rbtree_node_t *x;

                x = tree->allocator.alloc(sizeof(struct rbtree_node));
                INIT_NODE(x, n, key, data);
                n->right = x;
                return x;
            }
            n = n->right;
        } else {
            break;
        }
    }
    return tree->nil;
}

void rbtree_remove(rbtree_t *tree, void *key)
{
    rbtree_node_t *z;

    z = tree->root;
    while (z) {
        if (tree->comp(key, z->key) < 0)  {
            z = z->left;
        } else if (tree->comp(key, z->key) > 0) {
            z = z->right;
        } else {
            rbtree_node_t *y;
            rbtree_node_t *x;

            /* get the node to splice out */
            if (z->left == tree->nil || z->right == tree->nil) {
                y = z;
            } else {
                y = get_successor(tree, z);
            }

            /* x is set to the non-NULL child of y or nil if y has no children */
            if (y->left != tree->nil) {
                x = y->left;
            } else {
                x = y->right;
            }
            x->parent = y->parent;

            /* splice out y */
            if (y->parent == tree->nil) {
                tree->root = x;
            } else if (y == y->parent->left) {
                y->parent->left = x;
            } else {
                y->parent->right = x;
            }
            if (y != z) {
                z->key = y->key;
                z->data = y->data;
            }

            /* if the deleted node is red, we still have a red-black tree */
            if (y->colour == BLACK) {
                remove_fixup(tree, x);
            }
            if (tree->free_key) {
                tree->free_key(y->key);
            }
            if (tree->free_data) {
                tree->free_data(y->data);
            }
            if (tree->allocator.dealloc) {
                tree->allocator.dealloc(y);
            }
            tree->size--;
            break;
        }
    }
}

/*
 * If the deleted node is black and has a red child, then we restore the
 * red-black tree by recolouring the child black. Hence, we are left with the
 * problem of restoring a red-black tree when the deleted node and all its
 * children are black. In this case, property 3 is violated because any path
 * that starts at a given node y, goes through the parent of the deleted node,
 * and then goes on to the "spliced-in child" and down to a descendant leaf will
 * have one too few black nodes than does a path from y to a leaf node that
 * doesn't go through the "spliced-in child".
 */
void remove_fixup(rbtree_t *tree, rbtree_node_t *x)
{
    while (x != tree->root && x->colour == BLACK) {
        if (x == x->parent->left) {
            rbtree_node_t *w; /* x's sibling */

            /* x's parent will have two children because of property 4 */
            w = x->parent->right;
            if (w->colour == RED) { /* case 1: x's sibling is red */
                w->colour = BLACK;
                w->parent->colour = RED;
                left_rotate(tree, x->parent);
                w = x->parent->right;
            }
            if (w->left->colour == BLACK && w->right->colour == BLACK) {
                /* case 2: the sibling's children are black */
                w->colour = RED;
                x = x->parent;
            } else {
                if (w->left->colour == RED) { /* case 3: the sibling's left child is red */
                    w->colour = RED;
                    w->left->colour = BLACK;
                    right_rotate(tree, w);
                    w = x->parent->right;
                }
                /* case 4: the sibling's right child is red */
                w->right->colour = BLACK;
                w->colour = x->parent->colour;
                x->parent->colour = BLACK;
                left_rotate(tree, x->parent);
                x = tree->root;
            }
        } else { /* x is a right child */
            rbtree_node_t *w; /* x's sibling */

            w = x->parent->left;
            if (w->colour == RED) { /* case 1: x's sibling is red */
                w->colour = BLACK;
                w->parent->colour = RED;
                right_rotate(tree, x->parent);
                w = x->parent->left;
            }
            if (w->left->colour == BLACK && w->right->colour == BLACK) {
                /* case 2: the sibling's children are black */
                w->colour = RED;
                x = x->parent;
            } else {
                if (w->right->colour == RED) { /* case 3: the sibling's right child is red */
                    w->colour = RED;
                    w->right->colour = BLACK;
                    left_rotate(tree, w);
                    w = x->parent->left;
                }
                /* case 4: the sibling's left child is red */
                w->left->colour = BLACK;
                w->colour = x->parent->colour;
                x->parent->colour = BLACK;
                right_rotate(tree, x->parent);
                x = tree->root;
            }
        }
    }
    x->colour = BLACK;
}

/*
 * A left rotation swaps the parent with its right child while preserving the
 * inorder property of the tree
 */
void left_rotate(rbtree_t *tree, rbtree_node_t *p)
{
    rbtree_node_t *c;
    rbtree_node_t *gp;

    c = p->right;
    gp = p->parent;
    p->right = c->left;
    if (c->left != tree->nil) {
        c->left->parent = p;
    }
    if (gp == tree->nil) {
        tree->root = c;
    } else if (gp->left == p) {
        gp->left = c;
    } else {
        gp->right = c;
    }
    c->left = p;
    c->parent = gp;
    p->parent = c;
}

/*
 * A right rotation swaps the parent with its left child while preserving the
 * inorder property of the tree
 */
void right_rotate(rbtree_t *tree, rbtree_node_t *p)
{
    rbtree_node_t *c;
    rbtree_node_t *gp;

    c = p->left;
    gp = p->parent;
    p->left = c->right;
    if (c->right != tree->nil) {
        c->right->parent = p;
    }
    if (gp == tree->nil) {
        tree->root = c;
    } else if (gp->left == p) {
        gp->left = c;
    } else {
        gp->right = c;
    }
    c->right = p;
    c->parent = gp;
    p->parent = c;
}

/* Get the node with the smallest key greater than n->key */
rbtree_node_t *get_successor(rbtree_t *tree, rbtree_node_t *n)
{
    if (n->right != tree->nil) {
        return get_minimum(tree, n->right);
    }
    rbtree_node_t *p = n->parent;

    while (p != tree->nil && n == p->right) {
        n = p;
        p = p->parent;
    }
    return p;
}

rbtree_node_t *get_minimum(rbtree_t *tree, rbtree_node_t *n)
{
    while (n->left != tree->nil) {
        n = n->left;
    }
    return n;
}

const rbtree_node_t *rbtree_first(rbtree_t *tree)
{
    return get_minimum(tree, tree->root);
}

const rbtree_node_t *rbtree_next(rbtree_t *tree, const rbtree_node_t *node)
{
    rbtree_node_t *s = get_successor(tree, (rbtree_node_t *) node);

    if (s == tree->nil) {
        return NULL;
    }
    return s;
}

void *rbtree_get_key(const rbtree_node_t *node)
{
    return node->key;
}

void *rbtree_get_data(const rbtree_node_t *node)
{
    return node->data;
}

void *rbtree_data(rbtree_t *tree, void *key)
{
    rbtree_node_t *n = tree->root;

    while (n != tree->nil) {
        if (tree->comp(key, n->key) < 0) {
            n = n->left;
        } else if (tree->comp(key, n->key) > 0) {
            n = n->right;
        } else {
            return n->data;
        }
    }
    return NULL;
}

bool rbtree_contains(rbtree_t *tree, void *key)
{
    rbtree_node_t *n = tree->root;

    while (n != tree->nil) {
        if (tree->comp(key, n->key) < 0)
            n = n->left;
        else if (tree->comp(key, n->key) > 0)
            n = n->right;
        else
            return true;
    }
    return false;
}

int rbtree_size(rbtree_t *tree)
{
    return tree->size;
}

void free_nodes(rbtree_t *tree, rbtree_node_t *n)
{
    if (n == tree->nil) return;

    free_nodes(tree, n->left);
    free_nodes(tree, n->right);
    if (tree->free_key) {
        tree->free_key(n->key);
    }
    if (tree->free_data) {
        tree->free_data(n->data);
    }
    if (tree->allocator.dealloc) {
        tree->allocator.dealloc(n);
    }
}

void rbtree_set_free_key(rbtree_t *tree, rbtree_deallocate fn)
{
    tree->free_key = fn;
}

void rbtree_set_free_data(rbtree_t *tree, rbtree_deallocate fn)
{
    tree->free_data = fn;
}
