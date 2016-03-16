#ifndef OUTPUT_H
#define OUTPUT_H

#include <ncurses.h>
#include "packet.h"

/* initialize ncurses */
void init_ncurses();

/* end ncurses mode */
void end_ncurses();

void get_input();

/*
 * Create the default layout of the screen. It will make two windows. One
 * containing the header, and below that the main screen with packet information.
 */
void create_layout();

/* print the rate of the transmission */
void print_rate();

/* print ARP frame information */
void print_arp(struct arp_info *info);

/* print IP packet information */
void print_ip(struct ip_info *info);

#endif
