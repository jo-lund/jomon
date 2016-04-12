#ifndef VECTOR_H
#define VECTOR_H

typedef void (*deallocate)(void *);

/* initialize vector with size of sz */
void vector_init(int sz, deallocate func);

/* insert element at the end */
void vector_push_back(void *data);

/* Remove element at the end. Total capacity will not be reduced */
void vector_pop_back();

/* get data from end of vector */
void *vector_back();

/* Get the ith element. Return null if no element */
void *vector_get_data(int i);

/* Get the number of elements stored in the vector */
int vector_size();

/* clear the vector and deallocate all memory */
void vector_clear();

#endif
