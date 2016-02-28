#include <stdlib.h>
#include "list.h"

typedef struct node {
    void *data;
    struct node *next;
    struct node *prev;
} node_t;

static node_t *head = NULL;
static node_t *tail = NULL;

#define INIT_NODE(n) n = malloc(sizeof(node_t));\
    n->data = data;
    n->next = NULL;
    n->prev = NULL;

const void *get_data(const node_t *n)
{
    return n->data;
}

void push_back(void *data)
{
    if (!head) {
        INIT_NODE(head);
        tail = head;
    } else if (head == tail) {
        node_t *node;

        INIT_NODE(node);
        head->next = node;
        node->prev = head;
        tail = node;
    } else {
        node_t *node;

        INIT_NODE(node);
        tail->next = node;
        node->prev = tail;
        tail = node;
    }
}

void push_front(void *data)
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
}

void pop_back()
{
    if (tail) {
        node_t *t = tail;

        tail = t->prev;
        free(t->data);
        free(t);
    }
}

void pop_front()
{
    if (head) {
        node_t *h = head;

        head = h->next;
        free(h->data);
        free(h);
    }
}

const void *back()
{
    if (tail) {
        return tail->data;
    }
    return NULL;
}

const void *front()
{
    if (head) {
        return head->data;
    }
    return NULL;
}

const node_t *begin()
{
    return head;
}

const node_t *end()
{
    return tail;
}

const node_t *get_prev(const node_t *n)
{
    if (n) {
        return n->prev;
    }
    return NULL;
}

const node_t *get_next(const node_t *n)
{
    if (n) {
        return n->next;
    }
    return NULL;
}

void clear_list()
{
    node_t *n = head;

    while (n) {
        node_t *tmp = n;

        n = n->next;
        free(tmp->data);
        free(tmp);
    }
}
