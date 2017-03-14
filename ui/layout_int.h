#ifndef LAYOUT_INT_H
#define LAYOUT_INT_H

#include <ncurses.h>

#define KEY_ESC 27
#define NUM_SCREENS 2

enum {
    HELP_SCREEN,
    STAT_SCREEN
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
    int type;
    bool focus;
    WINDOW *win;
} screen;

extern screen *screens[NUM_SCREENS];

/* push the screen with type 'scr' on the screen stack */
void push_screen(int scr);

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

bool is_capturing();

#endif
