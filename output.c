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
#define STATUS_HEIGHT 1

typedef node_t line;

static WINDOW *wheader;
static WINDOW *wmain;
static WINDOW *wstatus;

static int outy = 0;
static int interactive = 0;

/* keep a pointer to the top and bottom line */
static const line *top;
static const line *bottom;

static void print_header();
static void scroll_window();
static void print(char *buf);

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
    list_clear();
}

void create_layout()
{
    wheader = newwin(HEADER_HEIGHT, COLS, 0, 0);
    wmain = newwin(LINES - HEADER_HEIGHT - STATUS_HEIGHT, COLS, HEADER_HEIGHT, 0);
    wstatus = newwin(STATUS_HEIGHT, COLS, LINES - STATUS_HEIGHT, 0);
    nodelay(wmain, TRUE); /* input functions must be non-blocking */
    keypad(wmain, TRUE);
    print_header();
    scrollok(wmain, TRUE); /* enable scrolling */
    wsetscrreg(wmain, 0, LINES - HEADER_HEIGHT);
}

/* scroll the window if necessary */
void scroll_window()
{
    if (!top) top = list_begin();
    if (outy >= LINES - HEADER_HEIGHT - STATUS_HEIGHT) {
        outy = LINES - HEADER_HEIGHT - STATUS_HEIGHT - 1;
        scroll(wmain);
        top = list_next(top);
        bottom = list_end();
    }
}

void get_input()
{
    int c = 0;
    const char *buffer;

    c = wgetch(wmain);
    switch (c) {
    case 'i':
        if (interactive) {
            if (outy >= LINES - HEADER_HEIGHT - STATUS_HEIGHT) {
                const line *n = list_end();

                werase(wmain);
                for (int i = LINES - HEADER_HEIGHT - STATUS_HEIGHT - 1; i >= 0 && n; i--) {
                    mvwprintw(wmain, i, 0, "%s", list_data(n));
                    n = list_prev(n);
                }
                top = n;
                wrefresh(wmain);
            }
            interactive = 0;
            werase(wstatus);
            wrefresh(wstatus);
        } else {
            interactive = 1;
            mvwprintw(wstatus, 0, 0, "(interactive)");
            wrefresh(wstatus);
        }
        break;
    case 'q':
        break;
    case KEY_UP:
        if (list_prev(top)) {
            top = list_prev(top);
            bottom = list_prev(bottom);
            wscrl(wmain, -1);
            buffer = list_data(top);
            mvwprintw(wmain, 0, 0, buffer);
            wrefresh(wmain);
        }
        break;
    case KEY_DOWN:
        if (list_next(bottom)) {
            bottom = list_next(bottom);
            top = list_next(top);
            wscrl(wmain, 1);
            buffer = list_data(bottom);
            mvwprintw(wmain, LINES - HEADER_HEIGHT - STATUS_HEIGHT - 1, 0, buffer);
            wrefresh(wmain);
        }
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

void print(char *buf)
{
    list_push_back(buf); /* need to buffer every line */
    if (!interactive || (interactive && outy < LINES - HEADER_HEIGHT - STATUS_HEIGHT)) {
        scroll_window();
        mvwprintw(wmain, outy, 0, "%s", buf);
        outy++;
        wrefresh(wmain);
    }
}

void print_arp(struct arp_info *info)
{
    char *buffer;

    buffer = malloc(COLS + 1);
    switch (info->op) {
    case ARPOP_REQUEST:
        snprintf(buffer, COLS + 1, "%-18s%-18s%-10sARP request: Looking for hardware address of %s", info->sip, info->tip, "ARP", info->tip);
        break;
    case ARPOP_REPLY:
        snprintf(buffer, COLS + 1, "%-18s%-18s%-10sARP reply: %s has hardware address %s", info->sip, info->tip, "ARP", info->sip, info->sha);
        break;
    default:
        snprintf(buffer, COLS + 1, "%-18s%-18s%-10sOpcode %d", info->sip, info->tip, "ARP", info->op);
        break;
    }
    print(buffer);
}

void print_ip(struct ip_info *info)
{
    char *buffer;

    buffer = malloc(COLS + 1);
    snprintf(buffer, COLS + 1, "%-18s%-18s%-10s", info->src, info->dst, "IP");
    print(buffer);
}
