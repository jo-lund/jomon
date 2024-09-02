#include <stdlib.h>
#include <assert.h>
#include "stack.h"
#include "wrapper.h"

struct stack {
    void **buf;
    int top;
    int size;
};

stack *stack_init(int n)
{
    stack *s;

    assert(n > 0);
    s = xmalloc(sizeof(stack));
    s->buf = xmalloc(n * sizeof(void*));
    s->top = 0;
    s->size = n;
    return s;
}

bool stack_push(stack *s, void *data)
{
    if (s->top < s->size) {
        s->buf[s->top++] = data;
        return true;
    }
    return false;
}

void *stack_pop(stack *s)
{
    if (s->top > 0)
        return s->buf[--s->top];
    return NULL;
}

void stack_pop_free(stack *s, stack_deallocate func)
{
    if (s->top > 0)
        func(s->buf[--s->top]);
}

void *stack_top(stack *s)
{
    if (s->top > 0)
        return s->buf[s->top-1];
    return NULL;
}

void *stack_get(stack *s, int i)
{
    assert(i >= 0);
    if (i < s->size)
        return s->buf[i];
    return NULL;
}

void stack_clear(stack *s)
{
    s->size = 0;
    s->top = 0;
}

bool stack_empty(stack *s)
{
    return s->top == 0;
}

int stack_size(stack *s)
{
    return s->top;
}

void stack_free(stack *s, stack_deallocate func)
{
    if (func) {
        for (int i = 0; i < s->top; i++) {
            func(s->buf[i]);
        }
    }
    free(s->buf);
    free(s);
}
