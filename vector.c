#include <stdlib.h>
#include "vector.h"

#define FACTOR 1.5

typedef struct item {
    void *data;
} item_t;

struct vector {
    item_t *buf;
    unsigned int c;
    unsigned int size;
    vector_deallocate func;
};

vector_t *vector_init(int sz)
{
    vector_t *vector;

    vector = malloc(sizeof(vector_t));
    vector->size = sz;
    vector->c = 0;
    vector->buf = (item_t *) malloc(vector->size * sizeof(struct item));

    return vector;
}

void vector_push_back(vector_t *vector, void *data)
{
    if (data) {
        if (vector->c >= vector->size) {
            item_t *newbuf;

            newbuf = (item_t *) realloc(vector->buf, vector->size * sizeof(struct item) * FACTOR);
            vector->buf = newbuf;
            vector->size = vector->size * FACTOR;
        }
        vector->buf[vector->c++].data = data;
    }
}

inline void vector_pop_back(vector_t *vector, vector_deallocate func)
{
    if (vector->c) {
        if (func) {
            func(vector->buf[vector->c].data);
        }
        vector->c--;
    }
}

inline void *vector_back(vector_t *vector)
{
    if (vector->c) {
        return vector->buf[vector->c - 1].data;
    }
    return NULL;
}

inline void *vector_get_data(vector_t *vector, int i)
{
    if (i < vector->c) {
        return vector->buf[i].data;
    }
    return NULL;
}

inline int vector_size(vector_t *vector)
{
    return vector->c;
}

void vector_clear(vector_t *vector, vector_deallocate func)
{
    for (unsigned int i = 0; i < vector->c; i++) {
        if (func) {
            func(vector->buf[i].data);
        }
    }
    vector->c = 0;
}

void vector_free(vector_t *vector, vector_deallocate func)
{
    vector_clear(vector, func);
    vector->size = 0;
    free(vector->buf);
    free(vector);
}
