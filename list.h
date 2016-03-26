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

/* get data from front of the list */
const void *list_front();

/* get data from end of the list */
const void *list_back();

/* return pointer to beginning of list */
const node_t *list_begin();

/* return pointer to end of list */
const node_t *list_end();

/* return pointer to the ith element */
const node_t *list_ith(int index);

/* get previous node */
const node_t *list_prev(const node_t *n);

/* get next node */
const node_t *list_next(const node_t *n);

/* get the data stored in node n */
const void *list_data(const node_t *n);

#endif
