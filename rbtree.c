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

#define INIT_NODE(n, p, k)                       \
    do {                                         \
        n = malloc(sizeof(node_t));              \
        n->key = k;                              \
        n->colour = RED;                         \
        n->left = NULL;                          \
        n->right = NULL;                         \
        n->parent = p;                           \
    } while (0)

static node_t *insert_node(rbtree_t *tree, int key);
static void left_rotate(node_t *n);
static void right_rotate(node_t *n);
static void free_nodes(node_t *n);

rbtree_t *rbtree_init()
{
    rbtree_t *tree = malloc(sizeof(rbtree_t));

    tree->root = NULL;
    return tree;
}

void rbtree_free(rbtree_t *tree)
{
    free_nodes(tree->root);
    free(tree);
}

void rbtree_insert(rbtree_t *tree, int key)
{
    if (!tree->root) {
        INIT_NODE(tree->root, NULL, key);
    } else {
        node_t *x;

        x = insert_node(tree, key);
        if (!x) return;
        while (x != tree->root && x->parent->colour == RED) {
            if (x->parent == x->parent->parent->left) { /* parent is a left child */
                node_t *y = x->parent->parent->right; /* the parent's sibling */

                /* case 1: x's parent and the parent's sibling are both red */
                if (y && y->colour == RED) {
                    x->parent->colour = BLACK;
                    y->colour = BLACK;
                    x->parent->parent->colour = RED;
                    x = x->parent->parent;
                } else {
                    if (x == x->parent->right) {
                        /* case 2: sibling is black and x is a right child */
                        x = x->parent;
                        left_rotate(x);
                    }
                    /* case 3: sibling is black and x is a left child */
                    x->parent->colour = BLACK;
                    x->parent->parent->colour = RED;
                    right_rotate(x->parent->parent);
                }
            } else { /* parent is a right child */
                node_t *y = x->parent->parent->left;

                /* case 1: x's parent and the parent's sibling are both red */
                if (y && y->colour == RED) {
                    x->parent->colour = BLACK;
                    y->colour = BLACK;
                    x->parent->parent->colour = RED;
                    x = x->parent->parent;
                } else {
                    if (x == x->parent->left) {
                        /* case 2: sibling is black and x is a left child */
                        x = x->parent;
                        right_rotate(x);
                    }
                    /* case 3: sibling is black and x is a right child */
                    x->parent->colour = BLACK;
                    x->parent->parent->colour = RED;
                    left_rotate(x->parent->parent);
                }
            }
        }
    }
    tree->root->colour = BLACK;
}

void rbtree_remove(rbtree_t *tree, int key)
{

}

node_t *insert_node(rbtree_t *tree, int key)
{
    node_t *n = tree->root;

    while (n) {
        if (key < n->key) {
            if (!n->left) {
                struct node *x;

                INIT_NODE(x, n, key);
                n->left = x;
                return x;
            }
            n = n->left;
        } else if (key > n->key) {
            if (!n->right) {
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
    return NULL;
}

/*
 * A left rotation swaps the parent with its right node while preserving the
 * inorder property of the tree
 */
void left_rotate(node_t *p)
{
    node_t *c;
    node_t *gp;

    c = p->right;
    gp = p->parent;
    p->right = c->left;
    if (c->left) {
        c->left->parent = p;
    }
    if (gp->left == p) {
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
void right_rotate(node_t *p)
{
    node_t *c;
    node_t *gp;

    c = p->left;
    gp = p->parent;
    p->left = c->right;
    if (c->right) {
        c->right->parent = p;
    }
    if (gp->left == p) {
        gp->left = c;
    } else {
        gp->right = c;
    }
    c->right = p;
    c->parent = gp;
    p->parent = c;
}

void free_nodes(node_t *n)
{
    if (!n) return;

    free_nodes(n->left);
    free_nodes(n->right);
    free(n);
}
