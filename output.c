#include <arpa/inet.h>
#include <net/if_arp.h>
#include "misc.h"
#include "output.h"
#include "list.h"

#define SOURCEX 0
#define DESTX 18
#define PROTX 36
#define INFOX 46
#define HEADER_HEIGHT 4

static WINDOW *wmain;
static WINDOW *wheader;
static int outy = 0;

static void print_header();
static void scroll_window();
static void store_line();

void init_ncurses()
{
    initscr(); /* initialize curses mode */
    cbreak(); /* disable line buffering */
    noecho();
    curs_set(0); /* make the cursor invisible */
    //use_default_colors();
    //start_color();
}

void end_ncurses()
{
    endwin(); /* end curses mode */
    clear_list();
}

void create_layout()
{
    wheader = newwin(HEADER_HEIGHT, COLS, 0, 0);
    wmain = newwin(LINES - HEADER_HEIGHT, COLS, HEADER_HEIGHT, 0);
    nodelay(wmain, TRUE); /* input functions must be non-blocking */
    keypad(wmain, TRUE);
    print_header();
    scrollok(wmain, TRUE); /* enable scrolling */
    wsetscrreg(wmain, 0, LINES - HEADER_HEIGHT);
}

/* scroll the window if necessary */
void scroll_window()
{
    if (outy >= LINES - HEADER_HEIGHT) {
        scroll(wmain);
        outy = LINES - HEADER_HEIGHT - 1;
    }
}

/* need to buffer every line */
void store_line()
{
    chtype *buffer;

    buffer = (chtype *) malloc((COLS + 1) * sizeof(chtype));
    mvwinchnstr(wmain, outy, 0, buffer, COLS);
    push_back(buffer);
}

void get_input()
{
    int c = 0;
    const chtype *buffer;

    c = wgetch(wmain);
    switch (c) {
    case 'q':
        //mvwprintw(wmain, outy++, 0, "q");
        break;
    case KEY_UP:
        //mvwprintw(wmain, outy++, 0, "KEY_UP");
        /* buffer = get_data(node); */
        /* for (int i = 0; buffer[i] != 0; i++) { */
        /*     mvwaddch(wmain, outy, i, buffer[i]); */
        /* } */
        /* wrefresh(wmain); */
        break;
    case KEY_DOWN:
        //mvwprintw(wmain, outy++, 0, "KEY_DOWN");
        /* wscrl(wmain, 1); */
        /* buffer = get_data(node); */
        /* for (int i = 0; buffer[i] != 0; i++) { */
        /*     mvwaddch(wmain, outy, i, buffer[i]); */
        /* } */
        /* wrefresh(wmain); */
        break;
    }
}

void print_header()
{
    char addr[INET_ADDRSTRLEN];
    int y = 0;

    mvwprintw(wheader, y, 0, "Listening on device: %s", device);
    inet_ntop(AF_INET, &local_addr->sin_addr, addr, sizeof(addr));
    mvwprintw(wheader, ++y, 0, "Local address: %s", addr);
    y += 2;
    if (!capture) {
        attron(A_BOLD);
        mvwprintw(wheader, y, 0, "RX:");
        mvwprintw(wheader, ++y, 0, "TX:");
        attroff(A_BOLD);
    } else {
        mvwprintw(wheader, y, SOURCEX, "Source");
        mvwprintw(wheader, y, DESTX, "Destination");
        mvwprintw(wheader, y, PROTX, "Protocol");
        mvwprintw(wheader, y, INFOX, "Info");
        mvwchgat(wheader, y, 0, -1, A_STANDOUT, 0, NULL);
    }
    wrefresh(wheader);
}

void print_rate()
{
    //int rxmbytes = rx.tot_bytes / (1024 * 1024);
    //int txmbytes = tx.tot_bytes / (1024 * 1024);
    //double rxmbitspsec = rx.kbps / 1024 * 8;
    //double txmbitspsec = tx.kbps / 1024 * 8;

    /* mvprintw(y - 1, 4, "%5.0f KB/s", rx.kbps); */
    /* mvprintw(y, 3, " %5.0f KB/s", tx.kbps); */
    //refresh();
}

void print_arp(struct arp_info *info)
{
    scroll_window();
    mvwprintw(wmain, outy, SOURCEX, "%s", info->sip);
    mvwprintw(wmain, outy, DESTX, "%s", info->tip);
    mvwprintw(wmain, outy, PROTX, "ARP");

    switch (info->op) {
    case ARPOP_REQUEST:
        mvwprintw(wmain, outy, INFOX, "ARP request: Looking for hardware address of %s", info->tip);
        break;
    case ARPOP_REPLY:
        mvwprintw(wmain, outy, INFOX, "ARP reply: %s has hardware address %s", info->sip, info->sha);
        break;
    default:
        break;
    }
    store_line();
    outy++;
    wrefresh(wmain);
}

void print_ip(struct ip_info *info)
{
    scroll_window();
    mvwprintw(wmain, outy, SOURCEX, "%s", info->src);
    mvwprintw(wmain, outy, DESTX, "%s", info->dst);
    mvwprintw(wmain, outy, PROTX, "IP");
    store_line();
    outy++;
    wrefresh(wmain);
}
