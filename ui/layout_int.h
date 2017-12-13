#ifndef LAYOUT_INT_H
#define LAYOUT_INT_H

#include <ncurses.h>
#include "../signal.h"

#define KEY_ESC 27

/* colours on default background  */
#define CYAN COLOR_PAIR(3)
#define GREEN COLOR_PAIR(4)
#define BLUE COLOR_PAIR(5)
#define BROWN COLOR_PAIR(6)
#define MAGENTA COLOR_PAIR(7)
#define RED COLOR_PAIR(8)
#define YELLOW (COLOR_PAIR(6) | A_BOLD)
#define LIGHT_BLUE (BLUE | A_BOLD)
#define PURPLE (MAGENTA | A_BOLD)
#define GREY (COLOR_PAIR(10) | A_BOLD)

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
    SUBLAYER,
    NUM_LAYERS
};

#define NUM_SCREENS 6 /* see enum screen_type */

enum screen_type {
    MAIN_SCREEN,
    HELP_SCREEN,
    STAT_SCREEN,
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

#define SCREEN_DEFAULTS .screen_init = screen_init, \
        .screen_free = screen_free,                 \
        .screen_refresh = screen_refresh

#define SCREEN_OPTS(...) ((struct screen_operations)   \
        { SCREEN_DEFAULTS, __VA_ARGS__ })

typedef struct screen {
    enum screen_type type;
    bool focus;
    WINDOW *win;
    struct screen_operations *op;
} screen;

typedef struct screen_operations {
    void (*screen_init)(screen *s);
    void (*screen_free)(screen *s);
    void (*screen_refresh)(screen *s);
    void (*screen_get_input)(screen *s);
} screen_operations;

typedef struct {
    bool focus;
    WINDOW *win;
} container;

extern publisher_t *screen_changed_publisher;
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

/* Create and render the help screen */
screen *help_screen_create();

/* Render the help screen */
void help_screen_render();


#endif
