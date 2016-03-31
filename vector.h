#ifndef VECTOR_H
#define VECTOR_H

/* initialize vector with size of sz */
void vector_init(int sz);

/* insert element at the end */
void vector_push_back(void *data);

/* Remove element at the end. Space will not be deallocated */
void vector_pop_back();

/* get data from end of the vector */
void *vector_back();

/* Get the ith element. Return null if no element */
void *vector_get_data(int i);

/* Get the number of elements stored in the vector */
int vector_size();

/* clear the vector and deallocate all memory */
void vector_clear();

#endif
