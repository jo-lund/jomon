#include <stdlib.h>
#include "list.h"

typedef struct node {
    void *data;
    struct node *next;
    struct node *prev;
} node_t;

static node_t *head = NULL;
static node_t *tail = NULL;
static int size = 0;

#define INIT_NODE(n)                             \
    do {                                         \
        n = malloc(sizeof(node_t));              \
        n->data = data;                          \
        n->next = NULL;                          \
        n->prev = NULL;                          \
    } while (0);

void list_push_back(void *data)
{
    if (!head) {
        INIT_NODE(head);
        tail = head;
    } else {
        node_t *node;

        INIT_NODE(node);
        tail->next = node;
        node->prev = tail;
        tail = node;
    }
    size++;
}

void list_push_front(void *data)
{
    if (!head) {
        INIT_NODE(head);
        tail = head;
    } else {
        node_t *node;

        INIT_NODE(node);
        head->prev = node;
        node->next = head;
        head = node;
    }
    size++;
}

void list_pop_back()
{
    if (tail) {
        node_t *t = tail;

        tail = t->prev;
        free(t->data);
        free(t);
        size--;
    }
}

void list_pop_front()
{
    if (head) {
        node_t *h = head;

        head = h->next;
        free(h->data);
        free(h);
        size--;
    }
}

inline const void *list_data(const node_t *n)
{
    if (n) {
        return n->data;
    }
    return NULL;
}

inline const void *list_back()
{
    if (tail) {
        return tail->data;
    }
    return NULL;
}

inline const void *list_front()
{
    if (head) {
        return head->data;
    }
    return NULL;
}

inline const node_t *list_begin()
{
    return head;
}

inline const node_t *list_end()
{
    return tail;
}

const node_t *list_ith(int index)
{
    node_t *n = head;

    for (int i = 0; i < index && n; i++) {
        n = n->next;
    }
    return n;
}

inline const node_t *list_prev(const node_t *n)
{
    if (n) {
        return n->prev;
    }
    return NULL;
}

inline const node_t *list_next(const node_t *n)
{
    if (n) {
        return n->next;
    }
    return NULL;
}

inline int list_size()
{
    return size;
}

void list_clear()
{
    node_t *n = head;

    while (n) {
        node_t *tmp = n;

        n = n->next;
        free(tmp->data);
        free(tmp);
    }
    head = NULL;
    tail = NULL;
    size = 0;
}
