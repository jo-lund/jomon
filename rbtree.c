#include <stdint.h>
#include <stdlib.h>
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

typedef struct node {
    int key; /* this should be made generic */
    uint8_t colour;
    struct node *parent;
    struct node *left;
    struct node *right;
} node_t;

struct rbtree {
    node_t *root;
};

#define INIT_NODE(n, p, k)                        \
    do {                                          \
        n = malloc(sizeof(node_t));               \
        n->key = k;                               \
        n->colour = RED;                          \
        n->left = nil;                            \
        n->right = nil;                           \
        n->parent = p;                            \
    } while (0)

static node_t *insert_node(rbtree_t *tree, int key);
static void remove_fixup(rbtree_t *tree, node_t *x);
static void left_rotate(rbtree_t *tree, node_t *n);
static void right_rotate(rbtree_t *tree, node_t *n);
static node_t *get_minimum(node_t *n);
static node_t *get_successor(node_t *n);
static void free_nodes(node_t *n);

static node_t *nil; /* sentinel node */

rbtree_t *rbtree_init()
{
    rbtree_t *tree = malloc(sizeof(rbtree_t));

    INIT_NODE(nil, NULL, -1);
    tree->root = nil;
    nil->colour = BLACK;
    return tree;
}

void rbtree_free(rbtree_t *tree)
{
    free_nodes(tree->root);
    free(tree);
    free(nil);
}

void rbtree_insert(rbtree_t *tree, int key)
{
    if (tree->root == nil) {
        INIT_NODE(tree->root, nil, key);
    } else {
        node_t *x;

        x = insert_node(tree, key);
        if (x == nil) return;
        while (x != tree->root && x->parent->colour == RED) {
            if (x->parent == x->parent->parent->left) { /* parent is a left child */
                node_t *y = x->parent->parent->right; /* the parent's sibling */

                /* case 1: x's parent and the parent's sibling are both red */
                if (y != nil && y->colour == RED) {
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
                node_t *y = x->parent->parent->left;

                /* case 1: x's parent and the parent's sibling are both red */
                if (y != nil && y->colour == RED) {
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
}

node_t *insert_node(rbtree_t *tree, int key)
{
    node_t *n = tree->root;

    while (n != nil) {
        if (key < n->key) {
            if (n->left == nil) {
                struct node *x;

                INIT_NODE(x, n, key);
                n->left = x;
                return x;
            }
            n = n->left;
        } else if (key > n->key) {
            if (n->right == nil) {
                struct node *x;

                INIT_NODE(x, n, key);
                n->right = x;
                return x;
            }
            n = n->right;
        } else {
            break;
        }
    }
    return nil;
}

void rbtree_remove(rbtree_t *tree, int key)
{
    node_t *z;

    z = tree->root;
    while (z) {
        if (key < z->key) {
            z = z->left;
        } else if (key > z->key) {
            z = z->right;
        } else {
            node_t *y;
            node_t *x;

            /* get the node to splice out */
            if (z->left == nil || z->right == nil) {
                y = z;
            } else {
                y = get_successor(z);
            }

            /* x is set to the non-NULL child of y or nil if y has no children */
            if (y->left != nil) {
                x = y->left;
            } else {
                x = y->right;
            }
            x->parent = y->parent;

            /* splice out y */
            if (y->parent == nil) {
                tree->root = x;
            } else if (y == y->parent->left) {
                y->parent->left = x;
            } else {
                y->parent->right = x;
            }
            if (y != z) {
                z->key = y->key;
            }

            /* if the deleted node is red, we still have a red-black tree */
            if (y->colour == BLACK) {
                remove_fixup(tree, x);
            }
            free(y);
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
void remove_fixup(rbtree_t *tree, node_t *x)
{
    while (x != tree->root && x->colour == BLACK) {
        if (x == x->parent->left) {
            node_t *w; /* x's sibling */

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
            node_t *w; /* x's sibling */

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
 * A left rotation swaps the parent with its right node while preserving the
 * inorder property of the tree
 */
void left_rotate(rbtree_t *tree, node_t *p)
{
    node_t *c;
    node_t *gp;

    c = p->right;
    gp = p->parent;
    p->right = c->left;
    if (c->left != nil) {
        c->left->parent = p;
    }
    if (gp == nil) {
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
 * A right rotation swaps the parent with its left node while preserving the
 * inorder property of the tree
 */
void right_rotate(rbtree_t *tree, node_t *p)
{
    node_t *c;
    node_t *gp;

    c = p->left;
    gp = p->parent;
    p->left = c->right;
    if (c->right != nil) {
        c->right->parent = p;
    }
    if (gp == nil) {
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
node_t *get_successor(node_t *n)
{
    if (n->right != nil) {
        return get_minimum(n->right);
    }
    node_t *p = n->parent;

    while (p != nil && n == p->right) {
        n = p;
        p = p->parent;
    }
    return p;
}

node_t *get_minimum(node_t *n)
{
    while (n->left != nil) {
        n = n->left;
    }
    return n;
}

void free_nodes(node_t *n)
{
    if (n == nil) return;

    free_nodes(n->left);
    free_nodes(n->right);
    free(n);
}
