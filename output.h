#ifndef OUTPUT_H
#define OUTPUT_H

#include <ncurses.h>

/* initialize ncurses */
void init_ncurses();

void print_header();

/* print the rate of the transmission */
void print_rate();

#endif
