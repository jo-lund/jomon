#include <stdlib.h>
#include "vector.h"
#include "wrapper.h"

#define FACTOR 1.5

struct vector {
    void **buf;
    unsigned int c;
    unsigned int size;
    vector_deallocate func;
};

vector_t *vector_init(int sz)
{
    vector_t *vector;

    vector = xmalloc(sizeof(vector_t));
    vector->size = sz;
    vector->c = 0;
    vector->buf = xmalloc(vector->size * sizeof(void*));
    return vector;
}

void vector_push_back(vector_t *vector, void *data)
{
    if (vector->c >= vector->size) {
        void **newbuf;

        newbuf = xrealloc(vector->buf, vector->size * sizeof(void*) * FACTOR);
        vector->buf = newbuf;
        vector->size = vector->size * FACTOR;
    }
    vector->buf[vector->c++] = data;
}

void vector_pop_back(vector_t *vector, vector_deallocate func)
{
    if (vector->c) {
        if (func) {
            func(vector->buf[vector->c - 1]);
        }
        vector->c--;
    }
}

void *vector_back(vector_t *vector)
{
    if (vector->c) {
        return vector->buf[vector->c - 1];
    }
    return NULL;
}

void *vector_get(vector_t *vector, int i)
{
    if ((unsigned int) i < vector->c) {
        return vector->buf[i];
    }
    return NULL;
}

int vector_size(vector_t *vector)
{
    return vector->c;
}

void *vector_data(vector_t *vector)
{
    return (void *) vector->buf;
}

void vector_clear(vector_t *vector, vector_deallocate func)
{
    if (func) {
        for (unsigned int i = 0; i < vector->c; i++) {
            func(vector->buf[i]);
        }
    }
    vector->c = 0;
}

void vector_free(vector_t *vector, vector_deallocate func)
{
    if (!vector)
        return;
    vector_clear(vector, func);
    vector->size = 0;
    free(vector->buf);
    free(vector);
}
