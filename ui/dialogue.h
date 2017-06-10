#ifndef DIALOGUE_H
#define DIALOGUE_H

#include "layout_int.h"
#include "button.h"
#include "../misc.h"
#include "../vector.h"

#define DIALOGUE_SET_TITLE(o, d, t) ((o)->dialogue_set_title(d, t))
#define DIALOGUE_RENDER(o) ((o)->dialogue_render(o))
#define LABEL_DIALOGUE_GET_INPUT(o) ((o)->label_dialogue_get_input(o))
#define FILE_DIALOGUE_GET_INPUT(o) ((o)->file_dialogue_get_input(o))

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

typedef struct label_dialogue {
    dialogue dialogue_base;
    char *label;
    button *ok;

    void (*label_dialogue_get_input)(struct label_dialogue *ld);
} label_dialogue;

struct stat;

enum file_selection_type {
    FS_LOAD,
    FS_SAVE
};

/* file selection dialogue */
typedef struct file_dialogue {
    dialogue dialogue_base;
    container list;
    container input;
    char path[MAXPATH + 1];
    int i;
    int num_files;
    int top;
    int list_height;
    vector_t *files;
    button *ok;
    button *cancel;
    int has_focus;
    enum file_selection_type type;

    void (*file_dialogue_get_input)(struct file_dialogue *fd);
} file_dialogue;

/* Create a new dialogue. It needs to be freed by calling 'dialogue_free' */
dialogue *dialogue_create(char *title);

/* free the memory associated with dialogue */
void dialogue_free(dialogue *d);

/* Create a new label dialogue. It needs to be freed with 'label_dialogue_free' */
label_dialogue *label_dialogue_create(char *title, char *label, button_action act, void *arg);

/* free the memory associated with label dialogue */
void label_dialogue_free(label_dialogue *ld);

/* Create a new file dialogue. It needs to be freed with 'file_dialogue_free' */
file_dialogue *file_dialogue_create(char *title, enum file_selection_type type,
                                    char *path, button_action ok, button_action cancel);

/* free the memory associated with input dialogue */
void file_dialogue_free(file_dialogue *fd);


#endif
