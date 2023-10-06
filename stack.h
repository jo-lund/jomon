#ifndef STACK_H
#define STACK_H

#include <stdbool.h>

typedef struct stack stack_t;
typedef void (*stack_deallocate)(void *);

/* Initializes stack with capacity n */
stack_t *stack_init(int n);

/* Pushes data on stack. Returns true if there is enough room */
bool stack_push(stack_t *stack, void *data);

/* Pops data from stack. Will not free memory associated with data */
void *stack_pop(stack_t *stack);

/* Pops data from stack and frees memory */
void stack_pop_free(stack_t *stack, stack_deallocate func);

/* Returns the item on top of stack */
void *stack_top(stack_t *stack);

/* Returns the ith item on the stack */
void *stack_get(stack_t *stack, int i);

/* Clears the stack. Does not free memory */
void stack_clear(stack_t *stack);

/* Returns whether the stack is empty or not */
bool stack_empty(stack_t *stack);

/* Returns the number of elements */
int stack_size(stack_t *stack);

/*
 * Frees memory used by stack. If func is specified it will also free memory
 * allocated for each element on the stack.
 */
void stack_free(stack_t *stack, stack_deallocate func);

#endif
