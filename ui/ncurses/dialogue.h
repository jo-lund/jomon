#ifndef DIALOGUE_H
#define DIALOGUE_H

#include "layout.h"
#include "button.h"
#include "screen.h"
#include "misc.h"
#include "vector.h"
#include "file.h"

#define DIALOGUE_SET_TITLE(o, d, t) ((o)->dialogue_set_title(d, t))
#define DIALOGUE_RENDER(o) ((o)->dialogue_render(o))
#define PROGRESS_DIALOGUE_UPDATE(o, n) ((o)->progress_dialogue_update(o, n))
#define LABEL_DIALOGUE_SET_ACTION(o, a, p) ((o)->label_dialogue_set_action(o, a, p))

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

    /* set the action to be performed on button press */
    void (*label_dialogue_set_action)(struct label_dialogue *ld, button_action act,
                                      void *arg);
} label_dialogue;

typedef struct decision_dialogue {
    dialogue dialogue_base;
    char *label;
    button *ok;
    button *cancel;
    int has_focus;
} decision_dialogue;

struct stat;

enum file_selection_type {
    FS_LOAD,
    FS_SAVE
};

/* file selection dialogue */
typedef struct file_dialogue {
    dialogue dialogue_base;
    container list;
    container dir;
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
} file_dialogue;

typedef struct progress_dialogue {
    dialogue dialogue_base;
    int percent;
    int size;
    int sum;
    int idx;
    int ypos;
    int xpos;
    void (*progress_dialogue_update)(struct progress_dialogue *pd, int n);
} progress_dialogue;

/* Create a new dialogue. It needs to be freed by calling 'dialogue_free' */
dialogue *dialogue_create(char *title);

/* free the memory associated with dialogue */
void dialogue_free(screen *s);

/* Create a new label dialogue. It needs to be freed by calling label_dialogue_free. */
label_dialogue *label_dialogue_create(char *title, char *label, button_action act, void *arg);

/* free the memory associated with label dialogue */
void label_dialogue_free(screen *s);

/* Create a new decision dialogue. It needs to be freed by calling decision_dialogue_free. */
decision_dialogue *decision_dialogue_create(char *title, char *label, button_action ok, void *ok_arg,
                                            button_action cancel, void *cancel_arg);

/* Free the memory associated with decision dialogue */
void decision_dialogue_free(screen *s);

/* Create a new file dialogue. It needs to be freed with 'file_dialogue_free' */
file_dialogue *file_dialogue_create(char *title, enum file_selection_type type,
                                    char *path, button_action ok, button_action cancel);

/* free the memory associated with file dialogue */
void file_dialogue_free(screen *s);

/* Create a progress dialogue. It needs to be freed with 'progress_dialogue_free' */
progress_dialogue *progress_dialogue_create(char *title, int size);

/* Free the memory associated with progress dialogue */
void progress_dialogue_free(screen *s);

/* General dialogues */
void create_file_error_dialogue(enum file_error err, void (*callback)(void));
void create_warning_dialogue(char *txt, void (*ok_callback)(void *), void *ok_arg,
                             void (*cancel_callback)(void *), void *cancel_arg);

#endif
