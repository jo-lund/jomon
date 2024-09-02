#ifndef STACK_H
#define STACK_H

#include <stdbool.h>

typedef struct stack stack;
typedef void (*stack_deallocate)(void *);

/* Initializes stack with capacity n */
stack *stack_init(int n);

/* Pushes data on stack. Returns true if there is enough room */
bool stack_push(stack *s, void *data);

/* Pops data from stack. Will not free memory associated with data */
void *stack_pop(stack *s);

/* Pops data from stack and frees memory */
void stack_pop_free(stack *s, stack_deallocate func);

/* Returns the item on top of stack */
void *stack_top(stack *s);

/* Returns the ith item on the stack */
void *stack_get(stack *s, int i);

/* Clears the stack. Does not free memory */
void stack_clear(stack *s);

/* Returns whether the stack is empty or not */
bool stack_empty(stack *s);

/* Returns the number of elements */
int stack_size(stack *s);

/*
 * Frees memory used by stack. If func is specified it will also free memory
 * allocated for each element on the stack.
 */
void stack_free(stack *s, stack_deallocate func);

#endif
