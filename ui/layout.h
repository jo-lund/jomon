#ifndef UI_LAYOUT_H
#define UI_LAYOUT_H

#include "../misc.h"

extern bool numeric;
struct packet;

/* initialize ncurses and create the screen layout */
void init_ncurses(bool capturing);

/* end ncurses mode */
void end_ncurses();

void handle_input();
void print_packet(struct packet *p);
void print_file();

#endif
