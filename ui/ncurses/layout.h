#ifndef LAYOUT_H
#define LAYOUT_H

#include <ncurses.h>

#define KEY_ESC 27
#define KEY_CTRL_DOWN 0x20e
#define KEY_CTRL_UP 0x237
#define NUM_THEMES 3
#define UPDATE_SELECTIONBAR(w, l, c) \
    mvwchgat(w, l, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(c)), NULL)

enum colour_themes {
    DEFAULT,
    LIGHT,
    DARK
};

enum elements {
    HEADER,
    HEADER_TXT,
    SUBHEADER_TXT,
    HELP_TXT,
    STATUS_BUTTON,
    BUTTON,
    DIALOGUE_BKGD,
    FD_LIST_BKGD,
    FD_INPUT_BKGD,
    FD_TEXT,
    DISABLE,
    FOCUS,
    SELECTIONBAR,
    BACKGROUND,
    MENU_BACKGROUND,
    MENU_SELECTIONBAR,
    SRC_TXT,
    DST_TXT,
    ERR_BKGD,
    MARK,
    NUM_ELEMENTS
};

enum layer {
    UI_LAYER1,
    UI_LAYER2,
    UI_LAYER3,
    UI_LAYER4,
    UI_SUBLAYER1,
    UI_SUBLAYER2,
    UI_FLAGS,
    NUM_LAYERS
};

enum screen_type {
    MAIN_SCREEN,
    HELP_SCREEN,
    STAT_SCREEN,
    CONNECTION_SCREEN,
    HOST_SCREEN,
    CONVERSATION_SCREEN,
    LABEL_DIALOGUE,
    FILE_DIALOGUE,
    PROGRESS_DIALOGUE,
    NUM_SCREENS
};

struct screen;
typedef struct actionbar actionbar_t;

typedef struct {
    bool focus;
    WINDOW *win;
} container;

extern bool selected[NUM_LAYERS];
extern actionbar_t *actionbar;

/* Allocates space for a new container. Needs to be freed with free_container() */
container *create_container(void);

/* Free the memory allocated for the container */
void free_container(container *c);

/*
 * Returns the screen with the specified type. Returns NULL if the screen
 * doesn't exist.
 */
struct screen *screen_cache_get(enum screen_type type);

/* Insert screen into screen cache */
void screen_cache_insert(enum screen_type st, struct screen *s);

/* Remove screen from screen cacne */
void screen_cache_remove(enum screen_type st);

/* Clear the screen cache. Will free the memory allocated for the screens. */
void screen_cache_clear(void);

/* Push the screen on the screen stack */
void push_screen(struct screen *s);

/* Pop the screen from the screen stack */
void pop_screen(void);

/* Return whether the screen stack is empty or not */
bool screen_stack_empty(void);

/* Return the size of the screen stack */
unsigned int screen_stack_size(void);

/* Get the topmost screen */
struct screen *screen_stack_top(void);

/* Get the screen behind the topmost screen */
struct screen *screen_stack_prev(void);

/*
 * Move screen to top of the screen stack. If screen is not part of the stack,
 * this will behave as push_screen.
 */
void screen_stack_move_to_top(struct screen *s);

/*
 * When the scrollok option is enabled ncurses will wrap long lines at the
 * bottom of the screen. This function will print without line wrapping. It will
 * move the cursor location to the given coordinates before printing.
 */
void mvprintnlw(WINDOW *win, int y, int x, int scrollx, const char *fmt, ...);

/*
 * Write the string 'str' to 'win' without line wrapping. It will move the cursor
 * location to the given coordinates before printing.
 */
void mvputsnlw(WINDOW *win, int y, int x, int scrollx, char *str);

/*
 * Print text in window with the specified attributes. It will start to print at
 * the current cursor location.
 */
void printat(WINDOW *win, int attrs, const char *fmt, ...);

/*
 * Print text in window with the specified attributes. It will move the cursor
 * location to the given coordinates before printing.
 */
void mvprintat(WINDOW *win, int y, int x, int attrs, const char *fmt, ...);

/* Return the element colour based on which theme is active */
int get_theme_colour(enum elements elem);

#endif
