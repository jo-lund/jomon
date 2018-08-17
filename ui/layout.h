#ifndef UI_LAYOUT_H
#define UI_LAYOUT_H

#include "../misc.h"

extern bool numeric;
struct packet;

/* initialize ncurses and create the screen layout */
void ncurses_init();

/* end ncurses mode */
void ncurses_end();

void layout(enum event ev);
void handle_input();
void print_file();

#endif
