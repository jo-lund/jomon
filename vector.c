#include <stdlib.h>
#include <assert.h>
#include "vector.h"
#include "wrapper.h"

#define FACTOR 1.5

struct vector {
    void **buf;
    int c;
    int size;
    vector_deallocate func;
};

vector_t *vector_init(int sz)
{
    vector_t *vector;

    assert(sz > 0);
    vector = xmalloc(sizeof(vector_t));
    vector->size = sz;
    vector->c = 0;
    vector->buf = xmalloc((size_t) vector->size * sizeof(void*));
    return vector;
}

void vector_push_back(vector_t *vector, void *data)
{
    if (vector->c >= vector->size) {
        void **newbuf;

        vector->size = (int) (vector->size * FACTOR);
        assert(vector->size > 0);
        newbuf = xrealloc(vector->buf, (size_t) vector->size * sizeof(void*));
        vector->buf = newbuf;
    }
    vector->buf[vector->c++] = data;
}

void vector_pop_back(vector_t *vector, vector_deallocate func)
{
    if (vector->c > 0) {
        if (func) {
            func(vector->buf[vector->c - 1]);
        }
        vector->c--;
    }
}

void *vector_back(vector_t *vector)
{
    if (vector->c > 0)
        return vector->buf[vector->c - 1];
    return NULL;
}

void *vector_get(vector_t *vector, int i)
{
    assert(i >= 0);
    if (i < vector->c)
        return vector->buf[i];
    return NULL;
}

int vector_size(vector_t *vector)
{
    return vector->c;
}

void **vector_data(vector_t *vector)
{
    return vector->buf;
}

void vector_clear(vector_t *vector, vector_deallocate func)
{
    if (func) {
        for (int i = 0; i < vector->c; i++) {
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
