#ifndef LAYOUT_INT_H
#define LAYOUT_INT_H

#include <ncurses.h>
#include "../signal.h"

#define KEY_ESC 27
#define NUM_SCREENS 2

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

enum screen_type {
    HELP_SCREEN,
    STAT_SCREEN,
    INPUT_DIALOGUE,
    LABEL_DIALOGUE
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
    NBNS_FLAGS,
    NBDS_FLAGS,
    SUBLAYER,
    NUM_LAYERS
};

typedef struct {
    enum screen_type type;
    bool focus;
    WINDOW *win;
} screen;

typedef struct {
    bool focus;
    WINDOW *win;
} container;

extern publisher_t *screen_changed_publisher;
extern bool selected[NUM_LAYERS];

/*
 * Allocates space for the specified screen type and returns a pointer to it.
 * Should only be used by derived classes. Needs to be freed with free_screen().
 */
screen *create_screen(enum screen_type type);

/* Free the memory allocated for screen */
void free_screen(screen *scr);

/* Allocates space for a new container. Needs to be freed with free_container() */
container *create_container();

/* Free the memory allocated for the container */
void free_container(container *c);

/*
 * Returns the screen with the specified type. Returns NULL if the screen
 * doesn't exist.
 */
screen *get_screen(enum screen_type type);

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
