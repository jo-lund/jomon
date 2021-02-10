#ifndef LIST_H
#define LIST_H

#include "alloc.h"

#define LIST_FOREACH(l, i) \
    for ((i) = list_begin(l); (i); (i) = list_next((i)))

typedef struct node node_t;
typedef struct list list_t;

/* User-defined function to deallocate memory for the data stored in list_t */
typedef void (*list_deallocate)(void *);

/*
 * Initializes list.
 *
 * Allocates resources for list that needs to be freed with list_free. If allocator
 * is specified this will be used to allocate/deallocate memory for list_t, else the
 * default allocator is used.
 */
list_t *list_init(allocator_t *allocator);

/* Inserts element at the front */
void list_push_front(list_t *list, void *data);

/* Inserts element at the end */
void list_push_back(list_t *list, void *data);

/* Inserts element at position 'i' */
void list_insert(list_t *list, void *data, int i);

/* Removes element from the front and deallocates memory for it if func is specified */
void list_pop_front(list_t *list, list_deallocate func);

/* Removes element from the end and deallocates memory for it if func is specified */
void list_pop_back(list_t *list, list_deallocate func);

/* Removes element from the list and deallocates memory for it if func is specified */
void list_remove(list_t *list, void *data, list_deallocate func);

/* Returns data from front of the list */
void *list_front(list_t *list);

/* Returns data from end of the list */
void *list_back(list_t *list);

/* Returns pointer to beginning of list */
const node_t *list_begin(list_t *list);

/* Returns pointer to end of list */
const node_t *list_end(list_t *list);

/* Returns pointer to the ith element */
const node_t *list_ith(list_t *list, int index);

/* Returns pointer to previous node */
const node_t *list_prev(const node_t *n);

/* Returns pointer to next node */
const node_t *list_next(const node_t *n);

/* Returns the data stored in node n */
void *list_data(const node_t *n);

/* Returns the number of elements */
int list_size(list_t *list);

/*
 * Clears the list
 *
 * If func is specified memory for data is deallocated but not the list_t
 * structure. To free all memory associated with list use list_free.
 */
list_t *list_clear(list_t *list, list_deallocate func);

/* Frees all memory used by list */
void list_free(list_t *list, list_deallocate func);

#endif
