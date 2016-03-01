#ifndef LIST_H
#define LIST_H

typedef struct node node_t;

/* insert element at the front */
void list_push_front(void *data);

/* insert element at the end */
void list_push_back(void *data);

/* remove element from the front */
void list_pop_front();

/* remove element from the end */
void list_pop_back();

/* clear the list */
void list_clear();

const void *list_front();

const void *list_back();

const node_t *list_begin();

const node_t *list_end();

const node_t *list_prev(const node_t *n);

const node_t *list_next(const node_t *n);

const void *list_data(const node_t *n);

#endif
