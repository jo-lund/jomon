#ifndef DIALOGUE_H
#define DIALOGUE_H

#include "layout_int.h"
#include "button.h"

#define DIALOGUE_SET_TITLE(o, d, t) ((o)->dialogue_set_title(d, t))
#define DIALOGUE_RENDER(o) ((o)->dialogue_render(o))
#define INPUT_DIALOGUE_GET_INPUT(o) ((o)->input_dialogue_get_input(o))
#define INPUT_DIALOGUE_SET_BUTTON_ACTION(o, a1, a2) \
    ((o)->input_dialogue_set_button_action(o, a1, a2))
#define INPUT_DIALOGUE_RENDER(o) ((o)->input_dialogue_render(o))

typedef struct dialogue {
    screen scr;
    char *title;
    int height;
    int width;

    /* set title of the dialogue */
    void (*dialogue_set_title)(struct dialogue *d, char *title);

    /* display the dialogue */
    void (*dialogue_render)(struct dialogue *d);
} dialogue;

typedef struct input_dialogue {
    char d[sizeof(dialogue)]; /* base class */
    container input;
    button *ok;
    button *cancel;
    int has_focus;
    char *input_txt;

    /* handle input */
    void (*input_dialogue_get_input)(struct input_dialogue *id);

    /* set handlers for the 'ok' and 'cancel' buttons */
    void (*input_dialogue_set_button_action)(struct input_dialogue *id, button_action ok,
                                             button_action cancel);

    /* display the input dialogue */
    void (*input_dialogue_render)(struct input_dialogue *id);
} input_dialogue;

/* create a new dialogue */
dialogue *dialogue_create(char *title);

/* free the memory associated with dialogue */
void dialogue_free(dialogue *d);

/* create a new input dialogue */
input_dialogue *input_dialogue_create(char *title, char *input, button_action ok,
                                      button_action cancel);

/* free the memory associated with input dialogue */
void input_dialogue_free(input_dialogue *id);

#endif
