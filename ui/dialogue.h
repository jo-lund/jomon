#ifndef DIALOGUE_H
#define DIALOGUE_H

#include "layout_int.h"
#include "button.h"

#define DIALOGUE_SET_TITLE(o, d, t) ((o)->dialogue_set_title(d, t))
#define DIALOGUE_RENDER(o) ((o)->dialogue_render(o))
#define FILE_INPUT_DIALOGUE_GET_INPUT(o) ((o)->file_input_dialogue_get_input(o))
#define FILE_INPUT_DIALOGUE_SET_INPUT(o, i) ((o)->file_input_dialogue_set_input(o, i))
#define FILE_INPUT_DIALOGUE_SET_BUTTON_ACTION(o, a1, a2)    \
    ((o)->file_input_dialogue_set_button_action(o, a1, a2))
#define FILE_INPUT_DIALOGUE_RENDER(o) ((o)->file_input_dialogue_render(o))
#define LABEL_DIALOGUE_GET_INPUT(o) ((o)->label_dialogue_get_input(o))

typedef struct dialogue {
    screen screen_base;
    char *title;
    int height;
    int width;

    /* set title of the dialogue */
    void (*dialogue_set_title)(struct dialogue *this, char *title);

    /* display the dialogue */
    void (*dialogue_render)(struct dialogue *this);
} dialogue;

typedef struct file_input_dialogue {
    dialogue dialogue_base;
    container input;
    button *ok;
    button *cancel;
    int has_focus;

    /* handle input */
    void (*file_input_dialogue_get_input)(struct file_input_dialogue *this);

    /* set the default input */
    void (*file_input_dialogue_set_input)(struct file_input_dialogue *this, char *input);

    /* set handlers for the 'ok' and 'cancel' buttons */
    void (*file_input_dialogue_set_button_action)(struct file_input_dialogue *this,
                                                  button_action ok,
                                                  button_action cancel);

    /* display the file_input dialogue */
    void (*file_input_dialogue_render)(struct file_input_dialogue *id);
} file_input_dialogue;

typedef struct label_dialogue {
    dialogue dialogue_base;
    char *label;
    button *ok;

    void (*label_dialogue_get_input)(struct label_dialogue *ld);

} label_dialogue;

/* Create a new dialogue. It needs to be freed by calling 'dialogue_free' */
dialogue *dialogue_create(char *title);

/* free the memory associated with dialogue */
void dialogue_free(dialogue *d);

/* Create a new file_input dialogue. It needs to be freed with 'file_input_dialogue_free' */
file_input_dialogue *file_input_dialogue_create(char *title, button_action ok,
                                                button_action cancel);

/* free the memory associated with file_input dialogue */
void file_input_dialogue_free(file_input_dialogue *id);

/* Create a new label dialogue. It needs to be freed with 'label_dialogue_free' */
label_dialogue *label_dialogue_create(char *title, char *label, button_action act);

/* free the memory associated with label dialogue */
void label_dialogue_free(label_dialogue *ld);

#endif
