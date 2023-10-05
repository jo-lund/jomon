#ifndef VECTOR_H
#define VECTOR_H

typedef struct vector vector_t;
typedef void (*vector_deallocate)(void *);

/* initialize vector with size of sz */
vector_t *vector_init(int sz);

/* insert element at the end */
void vector_push_back(vector_t *vector, void *data);

/* Remove element at the end. Total capacity will not be reduced */
void vector_pop_back(vector_t *vector, vector_deallocate func);

/* get data from end of vector */
void *vector_back(vector_t *vector);

/* Get the ith element. Return null if no element */
void *vector_get(vector_t *vector, int i);

/* Get the number of elements stored in the vector */
int vector_size(vector_t *vector);

/* Return the underlying array */
void **vector_data(vector_t *vector);

/*
 * Clears the vector
 *
 * Memory for the data is deallocated if func is specified, but not the vector.
 * To free all memory associated with vector use vector_free.
 */
void vector_clear(vector_t *vector, vector_deallocate func);

/* Free all memory used by vector */
void vector_free(vector_t *vector, vector_deallocate func);

#endif
