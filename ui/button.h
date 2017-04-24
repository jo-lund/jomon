#ifndef BUTTON_H
#define BUTTON_H

#include "layout_int.h"

#define BUTTON_SET_ACTION(o, a) ((o)->button_set_action(o, a))
#define BUTTON_RENDER(o) ((o)->button_render(o))
#define BUTTON_SET_FOCUS(o, f) ((o)->button_set_focus(o, f))

typedef void (*button_action)(void *);

typedef struct button {
    container c;
    char *txt;
    button_action action; /* Function that is called on button press */

    void (*button_set_action)(struct button *b, button_action act);
    void (*button_render)(struct button *b);
    void (*button_set_focus)(struct button *b, bool has_focus);
} button;

button *button_create(screen *scr, button_action act, char *txt, int y, int x);
void button_free(button *b);

#endif
