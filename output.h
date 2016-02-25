#ifndef OUTPUT_H
#define OUTPUT_H

#include <ncurses.h>
#include "packet.h"

/* initialize ncurses */
void init_ncurses();

void print_header();

/* print the rate of the transmission */
void print_rate();

/* print arp frame information */
void print_arp(struct arp_info *info);

#endif
