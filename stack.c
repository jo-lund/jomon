#include <stdlib.h>
#include "stack.h"

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

    stack = malloc(sizeof(_stack_t));
    stack->buf = malloc(n * sizeof(item_t));
    stack->top = 0;
    stack->size = n;
    return stack;
}

inline bool stack_push(_stack_t *stack, void *data)
{
    if (stack->top < stack->size) {
        stack->buf[stack->top++].data = data;
        return true;
    }
    return false;
}

inline void *stack_pop(_stack_t *stack)
{
    if (stack->top) {
        return stack->buf[--stack->top].data;
    }
    return NULL;
}

inline void stack_pop_free(_stack_t *stack, stack_deallocate func)
{
    if (stack->top) {
        func(stack->buf[--stack->top].data);
    }
}

inline void *stack_top(_stack_t *stack)
{
    if (stack->top) {
        return stack->buf[stack->top-1].data;
    }
    return NULL;
}

inline void stack_clear(_stack_t *stack)
{
    stack->size = 0;
    stack->top = 0;
}

bool stack_empty(_stack_t *stack)
{
    return stack->top == 0;
}

void stack_free(_stack_t *stack, stack_deallocate func)
{
    if (func) {
        for (int i = 0; i < stack->top; i++) {
            func(stack->buf[i].data);
        }
    }
    free(stack->buf);
    free(stack);
}
