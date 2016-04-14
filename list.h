#ifndef LIST_H
#define LIST_H

typedef struct node node_t;
typedef struct list list_t;

/* initialize list */
list_t *list_init();

/* insert element at the front */
list_t *list_push_front(list_t *list, void *data);

/* insert element at the end */
list_t *list_push_back(list_t *list, void *data);

/* remove element from the front */
list_t *list_pop_front(list_t *list);

/* remove element from the end */
list_t *list_pop_back(list_t *list);

/* clear the list -- this will deallocate all memory associated with list */
list_t *list_clear(list_t *list);

/* get data from front of the list */
const void *list_front(list_t *list);

/* get data from end of the list */
const void *list_back(list_t *list);

/* return pointer to beginning of list */
const node_t *list_begin(list_t *list);

/* return pointer to end of list */
const node_t *list_end(list_t *list);

/* return pointer to the ith element */
const node_t *list_ith(list_t *list, int index);

/* get previous node */
const node_t *list_prev(const node_t *n);

/* get next node */
const node_t *list_next(const node_t *n);

/* get the data stored in node n */
const void *list_data(const node_t *n);

/* return the number of elements */
int list_size(list_t *list);

#endif
