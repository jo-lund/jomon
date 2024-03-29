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
    allocator_t allocator;
    int size;
} list_t;

#define INIT_NODE(n, d)                          \
    do {                                         \
        (n)->data = d;                           \
        (n)->next = NULL;                        \
        (n)->prev = NULL;                        \
    } while (0)

list_t *list_init(allocator_t *allocator)
{
    list_t *list;

    if (allocator) {
        list = allocator->alloc(sizeof(list_t));
        list->allocator.alloc = allocator->alloc;
        list->allocator.dealloc = allocator->dealloc;
    } else {
        list = xmalloc(sizeof(list_t));
        allocator_init(&list->allocator);
    }
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
    return list;
}

void list_push_front(list_t *list, void *data)
{
    if (!list->head) {
        list->head = list->allocator.alloc(sizeof(node_t));
        INIT_NODE(list->head, data);
        list->tail = list->head;
    } else {
        node_t *node;

        node = list->allocator.alloc(sizeof(node_t));
        INIT_NODE(node, data);
        list->head->prev = node;
        node->next = list->head;
        list->head = node;
    }
    list->size++;
}

void list_push_back(list_t *list, void *data)
{
    if (!list->head) {
        list->head = list->allocator.alloc(sizeof(node_t));
        INIT_NODE(list->head, data);
        list->tail = list->head;
    } else {
        node_t *node;

        node = list->allocator.alloc(sizeof(node_t));
        INIT_NODE(node, data);
        list->tail->next = node;
        node->prev = list->tail;
        list->tail = node;
    }
    list->size++;
}

void list_insert(list_t *list, void *data, int i)
{
    if (i == 0) {
        list_push_front(list, data);
    } else if (i == list->size) {
        list_push_back(list, data);
    } else if (i < list->size) {
        node_t *n;
        node_t *node;

        node = list->allocator.alloc(sizeof(node_t));
        INIT_NODE(node, data);
        n = (node_t *) list_ith(list, i);
        n->prev->next = node;
        node->prev = n->prev;
        node->next = n;
        n->prev = node;
        list->size++;
    }
}

void list_pop_front(list_t *list, list_deallocate func)
{
    if (list->head) {
        node_t *h = list->head;

        list->head = h->next;
        if (list->head) {
            list->head->prev = NULL;
        }
        if (func) {
            func(h->data);
        }
        if (list->allocator.dealloc) {
            list->allocator.dealloc(h);
        }
        list->size--;
    }
}

void list_pop_back(list_t *list, list_deallocate func)
{
    if (list->tail) {
        node_t *t = list->tail;

        list->tail = t->prev;
        if (list->tail) {
            list->tail->next = NULL;
        }
        if (func) {
            func(t->data);
        }
        if (list->allocator.dealloc) {
            list->allocator.dealloc(t);
        }
        list->size--;
    }
}

void list_remove(list_t *list, void *data, list_deallocate func)
{
    node_t **n = &list->head;

    while (*n) {
        if ((*n)->data == data) {
            node_t *t = *n;

            *n = (*n)->next;
            if (*n) {
                (*n)->prev = t->prev;
            } else {
                list->tail = t->prev;
            }
            if (func) {
                func(t->data);
            }
            if (list->allocator.dealloc) {
                list->allocator.dealloc(t);
            }
        } else {
            n = &(*n)->next;
        }
    }
}

void *list_data(const node_t *n)
{
    if (n) {
        return n->data;
    }
    return NULL;
}

void *list_back(list_t *list)
{
    if (list->tail) {
        return list->tail->data;
    }
    return NULL;
}

void *list_front(list_t *list)
{
    if (list->head) {
        return list->head->data;
    }
    return NULL;
}

const node_t *list_begin(list_t *list)
{
    return list->head;
}

const node_t *list_end(list_t *list)
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

const node_t *list_prev(const node_t *n)
{
    if (n) {
        return n->prev;
    }
    return NULL;
}

const node_t *list_next(const node_t *n)
{
    if (n) {
        return n->next;
    }
    return NULL;
}

int list_size(list_t *list)
{
    return list->size;
}

list_t *list_clear(list_t *list, list_deallocate func)
{
    node_t *n = list->head;

    while (n) {
        node_t *tmp = n;

        n = n->next;
        if (func) {
            func(tmp->data);
        }
        if (list->allocator.dealloc) {
            list->allocator.dealloc(tmp);
        }
    }
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
    return list;
}

void list_free(list_t *list, list_deallocate func)
{
    list = list_clear(list, func);
    if (list->allocator.dealloc) {
        list->allocator.dealloc(list);
    }
}
