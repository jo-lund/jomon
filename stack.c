#include <stdlib.h>
#include "stack.h"
#include "wrapper.h"

typedef struct item {
    void *data;
} item_t;

struct stack {
    item_t *buf;
    unsigned int top;
    unsigned int size;
};

_stack_t *stack_init(unsigned int n)
{
    _stack_t *stack;

    stack = xmalloc(sizeof(_stack_t));
    stack->buf = xmalloc(n * sizeof(item_t));
    stack->top = 0;
    stack->size = n;
    return stack;
}

bool stack_push(_stack_t *stack, void *data)
{
    if (stack->top < stack->size) {
        stack->buf[stack->top++].data = data;
        return true;
    }
    return false;
}

void *stack_pop(_stack_t *stack)
{
    if (stack->top) {
        return stack->buf[--stack->top].data;
    }
    return NULL;
}

void stack_pop_free(_stack_t *stack, stack_deallocate func)
{
    if (stack->top) {
        func(stack->buf[--stack->top].data);
    }
}

void *stack_top(_stack_t *stack)
{
    if (stack->top) {
        return stack->buf[stack->top-1].data;
    }
    return NULL;
}

void *stack_get(_stack_t *stack, unsigned int i)
{
    if (i < stack->size) {
        return stack->buf[i].data;
    }
    return NULL;
}

void stack_clear(_stack_t *stack)
{
    stack->size = 0;
    stack->top = 0;
}

bool stack_empty(_stack_t *stack)
{
    return stack->top == 0;
}

unsigned int stack_size(_stack_t *stack)
{
    return stack->top;
}

void stack_free(_stack_t *stack, stack_deallocate func)
{
    if (func) {
        for (unsigned int i = 0; i < stack->top; i++) {
            func(stack->buf[i].data);
        }
    }
    free(stack->buf);
    free(stack);
}
