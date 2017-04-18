#ifndef UI_LAYOUT_H
#define UI_LAYOUT_H

#include <ncurses.h>
#include "../misc.h"

extern bool numeric;
struct packet;

/* initialize ncurses and create the screen layout */
void init_ncurses(bool is_capturing);

/* end ncurses mode */
void end_ncurses();

/* get input from user */
void get_input();

void print_packet(struct packet *p);

void print_file();

#endif
