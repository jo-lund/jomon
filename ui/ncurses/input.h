#ifndef INPUT_H
#define INPUT_H

#include "misc.h"

enum valid_keys {
    INPUT_ALL,
    INPUT_DIGITS
};

/* Initialize input structure */
struct input_state *input_init(WINDOW *win, const char *prompt);

/* Free all resources */
void input_free(struct input_state *s);

/* Set valid keys. Default is all */
void input_set_valid_keys(struct input_state *s, enum valid_keys valid);

/*
 * Add character to input and move the cursor accordingly. Return 0 if still in
 * edit mode, 1 in case of 'enter', or -1 in case of error.
 */
int input_edit(struct input_state *s, int c);

/* Add a new string at the prompt */
void input_add_string(struct input_state *s, char *str);

/* Add line to history */
void input_add_history(struct input_state *s, const char *line);

/* Clear the input and exit */
void input_exit(struct input_state *s);

/* Print prompt and activate cursor */
void input_print_prompt(struct input_state *s);

/* Return the current input buffer */
char *input_get_buffer(struct input_state *s);

/* Refresh the input window */
void input_refresh(struct input_state *s);

#endif
