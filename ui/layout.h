#ifndef UI_LAYOUT_H
#define UI_LAYOUT_H

#include "../misc.h"

extern bool numeric;
struct packet;

/* initialize ncurses and create the screen layout */
void init_ncurses();

/* end ncurses mode */
void end_ncurses();

void layout(enum event ev);
void handle_input();
void print_file();

#endif
