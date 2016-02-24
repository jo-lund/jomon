#include <arpa/inet.h>
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
    mvprintw(y + 1, 0, "Local address: %s", addr);
    y += 3;
    attron(A_BOLD);
    mvprintw(y, 0, "RX:");
    mvprintw(++y, 0, "TX:");
    //mvchgat(y, 0, -1, A_STANDOUT, 0, NULL);
    attroff(A_BOLD);
    refresh();
    //y++;
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
