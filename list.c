#include <stdlib.h>
#include "list.h"

typedef struct node {
    void *data;
    struct node *next;
    struct node *prev;
} node_t;

typedef struct list {
    node_t *head;
    node_t *tail;
    list_deallocate func;
    int size;
} list_t;

#define INIT_NODE(n)                             \
    do {                                         \
        n = malloc(sizeof(node_t));              \
        n->data = data;                          \
        n->next = NULL;                          \
        n->prev = NULL;                          \
    } while (0);

list_t *list_init(list_deallocate func)
{
    list_t *list;

    list = malloc(sizeof(list_t));
    list->head = NULL;
    list->tail = NULL;
    list->func = func;
    list->size = 0;

    return list;
}

void list_push_front(list_t *list, void *data)
{
    if (!list->head) {
        INIT_NODE(list->head);
        list->tail = list->head;
    } else {
        node_t *node;

        INIT_NODE(node);
        list->head->prev = node;
        node->next = list->head;
        list->head = node;
    }
    list->size++;
}

void list_push_back(list_t *list, void *data)
{
    if (!list->head) {
        INIT_NODE(list->head);
        list->tail = list->head;
    } else {
        node_t *node;

        INIT_NODE(node);
        list->tail->next = node;
        node->prev = list->tail;
        list->tail = node;
    }
    list->size++;
}

void list_pop_front(list_t *list)
{
    if (list->head) {
        node_t *h = list->head;

        list->head = h->next;
        list->head->prev = NULL;
        if (list->func) {
            list->func(h->data);
        } else {
            free(h->data);
        }
        free(h);
        list->size--;
    }
}

void list_pop_back(list_t *list)
{
    if (list->tail) {
        node_t *t = list->tail;

        list->tail = t->prev;
        list->tail->next = NULL;
        if (list->func) {
            list->func(t->data);
        } else {
            free(t->data);
        }
        free(t);
        list->size--;
    }
}

inline void *list_data(const node_t *n)
{
    if (n) {
        return n->data;
    }
    return NULL;
}

inline void *list_back(list_t *list)
{
    if (list->tail) {
        return list->tail->data;
    }
    return NULL;
}

inline void *list_front(list_t *list)
{
    if (list->head) {
        return list->head->data;
    }
    return NULL;
}

inline const node_t *list_begin(list_t *list)
{
    return list->head;
}

inline const node_t *list_end(list_t *list)
{
    return list->tail;
}

const node_t *list_ith(list_t *list, int index)
{
    node_t *n = list->head;

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

inline int list_size(list_t *list)
{
    return list->size;
}

list_t *list_clear(list_t *list)
{
    node_t *n = list->head;

    while (n) {
        node_t *tmp = n;

        n = n->next;
        if (list->func) {
            list->func(tmp->data);
        } else {
            free(tmp->data);
        }
        free(tmp);
    }
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;

    return list;
}

void list_free(list_t *list)
{
    list = list_clear(list);
    free(list);
}
