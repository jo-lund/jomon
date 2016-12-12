#ifndef UI_LAYOUT_H
#define UI_LAYOUT_H

#include <ncurses.h>
#include "../misc.h"

extern bool numeric;
struct packet;

enum layer {
    ETHERNET_LAYER,
    ARP,
    LLC,
    SNAP,
    STP,
    IP,
    IGMP,
    ICMP,
    TRANSPORT,
    APPLICATION,
    SUBLAYER,
    NUM_LAYERS
};

/* initialize ncurses */
void init_ncurses();

/* end ncurses mode */
void end_ncurses();

/* get input from user */
void get_input();

/*
 * Create the default layout of the screen. It will make three windows. One
 * containing the header, another the main screen with packet information, and
 * below that a statusbar.
 */
void create_layout(context *c);

/* print the rate of the transmission */
void print_rate();

void print_packet(struct packet *p);

void print_file();

#endif
