#ifndef LAYOUT_INT_H
#define LAYOUT_INT_H

#include <ncurses.h>
#include "../signal.h"

#define KEY_ESC 27
#define NUM_SCREENS 2

enum screen_type {
    HELP_SCREEN,
    STAT_SCREEN,
    DIALOGUE
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

/*
 * Allocates space for the specified screen type and returns a pointer to it.
 * Needs to be freed with free_screen().
 */
screen *create_screen(enum screen_type type);

/* free the memory allocated for screen */
void free_screen(screen *scr);

container *create_container();
void free_container(container *c);

/*
 * Return the screen with the specified type. If the screen doesn't exit, it will
 * be created by calling create_screen.
 */
screen *get_screen(enum screen_type type);

/* push the screen on the screen stack */
void push_screen(screen *scr);

/* pop the screen from the screen stack */
void pop_screen();

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

#endif
