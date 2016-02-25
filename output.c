#include <arpa/inet.h>
#include <net/if_arp.h>
#include "misc.h"
#include "output.h"

static int x = 0;
static int y = 0;

void init_ncurses()
{
    initscr(); /* initialize curses mode */
    nocbreak(); /* keep terminal in normal (cooked) mode (use line buffering) */
    noecho();
    curs_set(0); /* make the cursor invisible */
    //use_default_colors();
    //start_color();
}

void print_header()
{
    char addr[INET_ADDRSTRLEN];

    mvprintw(y, 0, "Listening on device: %s", device);
    inet_ntop(AF_INET, &local_addr->sin_addr, addr, sizeof(addr));
    mvprintw(++y, 0, "Local address: %s", addr);
    y += 2;
    if (!capture) {
        attron(A_BOLD);
        mvprintw(y, 0, "RX:");
        mvprintw(++y, 0, "TX:");
        attroff(A_BOLD);
    } else {
        mvprintw(y, 0, "Source");
        mvprintw(y, 15, "Destination");
        mvprintw(y, 30, "Protocol");
        mvprintw(y, 40, "Info");
        mvchgat(y, 0, -1, A_STANDOUT, 0, NULL);
    }
    y++;
    refresh();
}

void print_rate()
{
    int rxmbytes = rx.tot_bytes / (1024 * 1024);
    //int txmbytes = tx.tot_bytes / (1024 * 1024);
    double rxmbitspsec = rx.kbps / 1024 * 8;
    double txmbitspsec = tx.kbps / 1024 * 8;

    mvprintw(y - 1, 4, "%5.0f KB/s", rx.kbps);
    mvprintw(y, 3, " %5.0f KB/s", tx.kbps);
    refresh();
}

void print_arp(struct arp_info *info)
{
    mvprintw(y, 0, "%s", info->sip);
    mvprintw(y, 15, "%s", info->tip);
    mvprintw(y, 30, "ARP");

    switch (info->op) {
    case ARPOP_REQUEST:
        mvprintw(y, 40, "ARP request: Looking for hardware address of %s", info->tip);
        break;
    case ARPOP_REPLY:
        mvprintw(y, 40, "ARP reply: %s has hardware address %s", info->sip, info->sha);
        break;
    default:
        break;
    }
    y++;
    refresh();
}
