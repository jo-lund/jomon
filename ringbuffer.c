#include <stdlib.h>
#include "ringbuffer.h"
#include "monitor.h"

typedef struct ringbuffer {
    void **buf;
    int head;
    int tail;
    int size;
    int it;
} ringbuffer_t;

ringbuffer_t *ringbuffer_init(const int sz)
{
    ringbuffer_t *rb;

    rb = xcalloc(1, sizeof(*rb));
    rb->size = clp2(sz);
    rb->buf = xmalloc(rb->size * sizeof(void*));
    return rb;
}

void ringbuffer_free(ringbuffer_t *rb)
{
    free(rb->buf);
    free(rb);
}

void ringbuffer_push(ringbuffer_t *rb, void *data)
{
    if (((rb->head + 1) & (rb->size - 1)) == rb->tail)
        ringbuffer_pop(rb);
    rb->buf[rb->head] = data;
    rb->head = (rb->head + 1) & (rb->size - 1);
}

void *ringbuffer_pop(ringbuffer_t *rb)
{
    void *data;

    data = NULL;
    if (rb->head != rb->tail) {
        data = rb->buf[rb->tail];
        rb->tail = (rb->tail + 1) & (rb->size - 1);
    }
    return data;
}

int ringbuffer_size(ringbuffer_t *rb)
{
    return (rb->head - rb->tail) & (rb->size - 1);
}

int ringbuffer_capacity(ringbuffer_t *rb)
{
    return rb->size - ringbuffer_size(rb);
}

bool ringbuffer_empty(ringbuffer_t *rb)
{
    return rb->head == rb->tail;
}

const void *ringbuffer_first(ringbuffer_t *rb)
{
    if (ringbuffer_empty(rb))
        return NULL;
    rb->it = rb->tail;
    return rb->buf[rb->tail];
}

const void *ringbuffer_next(ringbuffer_t *rb)
{
    if (ringbuffer_empty(rb))
        return NULL;
    if (((rb->it + 1) & (rb->size - 1)) == rb->tail)
        return NULL;
    rb->it = (rb->it + 1) & (rb->size - 1);
    return rb->buf[rb->it];
}
