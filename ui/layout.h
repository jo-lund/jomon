#ifndef UI_LAYOUT_H
#define UI_LAYOUT_H

#include "../misc.h"

extern bool numeric;
struct packet;

enum event {
    LAYOUT_NEW_PACKET,
    LAYOUT_ALARM,
    LAYOUT_RESIZE
};

/* initialize ncurses and create the screen layout */
void ncurses_init(void);

/* end ncurses mode */
void ncurses_end(void);

/* handle layout events */
void layout(enum event ev);

/* handle key input */
void handle_input(void);

/* print file to screen */
void print_file(void);

#endif
