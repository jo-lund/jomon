#ifndef UI_LAYOUT_H
#define UI_LAYOUT_H

#include <ncurses.h>
#include "../misc.h"

extern bool numeric;
struct packet;

/* initialize ncurses */
void init_ncurses(bool is_capturing);

/* end ncurses mode */
void end_ncurses();

/* get input from user */
void get_input();

/*
 * Create the default layout of the screen. It will make three windows. One
 * containing the header, another the main screen with packet information, and
 * below that a statusbar.
 */
void create_layout();

void print_packet(struct packet *p);

void print_file();

#endif
