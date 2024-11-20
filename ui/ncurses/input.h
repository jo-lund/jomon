#ifndef INPUT_H
#define INPUT_H

#include "misc.h"

enum valid_keys {
    INPUT_ALL,
    INPUT_DIGITS
};

struct input_state *input_init(WINDOW *win, const char *prompt);
void input_free(struct input_state *s);
void input_set_valid_keys(struct input_state *s, enum valid_keys valid);
int input_edit(struct input_state *s, int c);
void input_clear(struct input_state *s);
const char *input_get_prompt(struct input_state *s);
char *input_get_buffer(struct input_state *s);
void input_refresh(struct input_state *s);

#endif
