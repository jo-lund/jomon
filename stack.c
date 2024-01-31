#include <stdlib.h>
#include <assert.h>
#include "stack.h"
#include "wrapper.h"

struct stack {
    void **buf;
    int top;
    int size;
};

stack_t *stack_init(int n)
{
    stack_t *stack;

    assert(n > 0);
    stack = xmalloc(sizeof(stack_t));
    stack->buf = xmalloc((size_t) n * sizeof(void*));
    stack->top = 0;
    stack->size = n;
    return stack;
}

bool stack_push(stack_t *stack, void *data)
{
    if (stack->top < stack->size) {
        stack->buf[stack->top++] = data;
        return true;
    }
    return false;
}

void *stack_pop(stack_t *stack)
{
    if (stack->top > 0)
        return stack->buf[--stack->top];
    return NULL;
}

void stack_pop_free(stack_t *stack, stack_deallocate func)
{
    if (stack->top > 0)
        func(stack->buf[--stack->top]);
}

void *stack_top(stack_t *stack)
{
    if (stack->top > 0)
        return stack->buf[stack->top-1];
    return NULL;
}

void *stack_get(stack_t *stack, int i)
{
    assert(i >= 0);
    if (i < stack->size)
        return stack->buf[i];
    return NULL;
}

void stack_clear(stack_t *stack)
{
    stack->size = 0;
    stack->top = 0;
}

bool stack_empty(stack_t *stack)
{
    return stack->top == 0;
}

int stack_size(stack_t *stack)
{
    return stack->top;
}

void stack_free(stack_t *stack, stack_deallocate func)
{
    if (func) {
        for (int i = 0; i < stack->top; i++) {
            func(stack->buf[i]);
        }
    }
    free(stack->buf);
    free(stack);
}
