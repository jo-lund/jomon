#ifndef LAYOUT_INT_H
#define LAYOUT_INT_H

#include <ncurses.h>
#include "../signal.h"

#define KEY_ESC 27
#define STATUS_HEIGHT 1
#define NUM_THEMES 3

enum colour_themes {
    DEFAULT,
    LIGHT,
    DARK
};

enum elements {
    HEADER,
    HEADER_TXT,
    SUBHEADER_TXT,
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
    NUM_ELEMENTS
};

enum layer {
    ETHERNET_LAYER,
    ARP,
    LLC,
    SNAP,
    STP,
    IP,
    IGMP,
    ICMP,
    PIM,
    TRANSPORT,
    APPLICATION,
    IPV4_FLAGS,
    STP_FLAGS,
    TCP_FLAGS,
    DNS_FLAGS,
    DNS_RECORDS,
    NBNS_FLAGS,
    NBNS_RECORDS,
    NBDS_FLAGS,
    SMB,
    SMB_FLAGS,
    SNMP_PDU,
    SNMP_VARS,
    HTTP_DATA,
    SUBLAYER,
    NUM_LAYERS
};

#define NUM_SCREENS 6 /* see enum screen_type */

enum screen_type {
    MAIN_SCREEN,
    HELP_SCREEN,
    STAT_SCREEN,
    CONNECTION_SCREEN,
    LABEL_DIALOGUE,
    FILE_DIALOGUE,
    PROGRESS_DIALOGUE
};

/*
 * Convenience macros that will call the functions defined in screen_operations.
 * The argument 'o' is a pointer to the screen.
 */
#define SCREEN_INIT(o) ((o)->op->screen_init(o))
#define SCREEN_FREE(o) ((o)->op->screen_free(o))
#define SCREEN_REFRESH(o) ((o)->op->screen_refresh(o))
#define SCREEN_GET_INPUT(o) ((o)->op->screen_get_input(o))
#define SCREEN_GOT_FOCUS(o) ((o)->op->screen_got_focus(o))
#define SCREEN_LOST_FOCUS(o) ((o)->op->screen_lost_focus(o))

#define SCREEN_DEFAULTS .screen_init = screen_init, \
        .screen_free = screen_free,                 \
        .screen_refresh = screen_refresh

#define SCREEN_OPS(...) ((struct screen_operations)   \
        { SCREEN_DEFAULTS, __VA_ARGS__ })

typedef struct screen {
    bool focus;
    WINDOW *win;
    struct screen_operations *op;
} screen;

typedef struct screen_operations {
    void (*screen_init)(screen *s);
    void (*screen_free)(screen *s);
    void (*screen_refresh)(screen *s);
    void (*screen_get_input)(screen *s);
    void (*screen_got_focus)(screen *s);
    void (*screen_lost_focus)(screen *s);
} screen_operations;

typedef struct {
    bool focus;
    WINDOW *win;
} container;

extern bool selected[NUM_LAYERS];

/* Create a screen object */
screen *screen_create(screen_operations *op);

/* Default screen constructor */
void screen_init(screen *s);

/* Default screen destructor */
void screen_free(screen *s);

/* Default function called on screen refresh */
void screen_refresh(screen *s);

/* Allocates space for a new container. Needs to be freed with free_container() */
container *create_container();

/* Free the memory allocated for the container */
void free_container(container *c);

/*
 * Returns the screen with the specified type. Returns NULL if the screen
 * doesn't exist.
 */
screen *screen_cache_get(enum screen_type type);

void screen_cache_insert(enum screen_type st, screen *s);
void screen_cache_remove(enum screen_type st);
void screen_cache_clear();

/* Push the screen on the screen stack */
void push_screen(screen *scr);

/* Pop the screen from the screen stack */
void pop_screen();

/* Return whether the screen stack is empty or not */
bool screen_stack_empty();

/* Get the screen behind the topmost screen */
screen *screen_stack_prev();

/*
 * When the scrollok option is enabled ncurses will wrap long lines at the
 * bottom of the screen. This function will print without line wrapping.
 */
void printnlw(WINDOW *win, char *str, int len, int y, int x, int scrollx);

/*
 * Print text in window with the given attributes. If 'y' and 'x' are -1, it will
 * start to print at the current cursor location.
 */
void printat(WINDOW *win, int y, int x, int attrs, const char *fmt, ...);

int get_theme_colour(enum elements elem);

#endif
