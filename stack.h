#ifndef STACK_H
#define STACK_H

#include <stdbool.h>

typedef struct stack _stack_t;
typedef void (*stack_deallocate)(void *);

/* Initializes stack with size n */
_stack_t *stack_init(unsigned int n);

/* Pushes data on stack. Returns true if there is enough room */
bool stack_push(_stack_t *stack, void *data);

/* Pops data from stack. Will not free memory associated with data */
void *stack_pop(_stack_t *stack);

/* Pops data from stack and frees memory */
void stack_pop_free(_stack_t *stack, stack_deallocate func);

/* Returns the item on top of stack */
void *stack_top(_stack_t *stack);

/* Clears the stack. Does not free memory */
void stack_clear(_stack_t *stack);

/* Returns whether the stack is empty or not */
bool stack_empty(_stack_t *stack);

/*
 * Frees memory used by stack. If func is specified it will also free memory
 * allocated for each element on the stack.
 */
void stack_free(_stack_t *stack, stack_deallocate func);

#endif
