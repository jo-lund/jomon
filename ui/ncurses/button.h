#ifndef BUTTON_H
#define BUTTON_H

#include "layout.h"

struct screen;

#define BUTTON_SET_ACTION(o, act, arg) ((o)->button_set_action(o, act, arg))
#define BUTTON_RENDER(o) ((o)->button_render(o))
#define BUTTON_SET_FOCUS(o, f) ((o)->button_set_focus(o, f))

typedef void (*button_action)(void *);

typedef struct button {
    container c;
    char *txt;
    button_action action; /* Function that is called on button press */
    void *argument;
    void (*button_set_action)(struct button *b, button_action act, void *arg);
    void (*button_render)(struct button *b);
    void (*button_set_focus)(struct button *b, bool has_focus);
} button;

button *button_create(struct screen *scr, button_action act, void *arg,
                      char *txt, int y, int x);
void button_free(button *b);

#endif
