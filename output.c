#include <arpa/inet.h>
#include <net/if_arp.h>
#include <string.h>
#include <netdb.h>
#include "misc.h"
#include "output.h"
#include "list.h"
#include "error.h"

#define SOURCEX 0
#define DESTX 36
#define PROTX 72
#define INFOX 82

#define HEADER_HEIGHT 4
#define STATUS_HEIGHT 1
#define HOSTNAMELEN 255 /* maximum 255 according to rfc1035 */

typedef node_t line;

static WINDOW *wheader;
static WINDOW *wmain;
static WINDOW *wstatus;
static int outy = 0;
static int interactive = 0;
static int numeric = 0;

/* keep a pointer to the top and bottom line */
static const line *top;
static const line *bottom;

static void print_header();
static void scroll_window();
static void print(char *buf);
static void gethost(char *addr, char *host, int hostlen);
static void print_udp(struct ip_info *info, char *buf, int n);

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
    case 'n':
        numeric = !numeric;
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
    int y = 0;
    char addr[INET_ADDRSTRLEN];

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
        snprintf(buffer, COLS + 1, "%-36s%-36s%-10sRequest: Looking for hardware address of %s",
                 info->sip, info->tip, "ARP", info->tip);
        break;
    case ARPOP_REPLY:
        snprintf(buffer, COLS + 1, "%-36s%-36s%-10sReply: %s has hardware address %s",
                 info->sip, info->tip, "ARP", info->sip, info->sha);
        break;
    default:
        snprintf(buffer, COLS + 1, "%-36s%-36s%-10sOpcode %d", info->sip, info->tip, "ARP", info->op);
        break;
    }
    print(buffer);
}

void print_ip(struct ip_info *info)
{
    char *buffer;
    int n = 0;;

    buffer = malloc(COLS + 1);
    if (!numeric && (info->protocol != IPPROTO_UDP ||
                     info->protocol == IPPROTO_UDP && info->udp.dns.qr == -1)) {
        char sname[HOSTNAMELEN];
        char dname[HOSTNAMELEN];

        /* get the host name of source and destination */
        gethost(info->src, sname, HOSTNAMELEN);
        gethost(info->dst, dname, HOSTNAMELEN);
        sname[35] = '\0';
        dname[35] = '\0';
        n = snprintf(buffer, COLS + 1, "%-36s%-36s", sname, dname);
    } else {
        n = snprintf(buffer, COLS + 1, "%-36s%-36s", info->src, info->dst);
    }

    switch (info->protocol) {
    case IPPROTO_ICMP:
        snprintf(buffer + n, COLS + 1 - n, "%-10s", "ICMP");
        break;
    case IPPROTO_IGMP:
        snprintf(buffer + n, COLS + 1 - n, "%-10s", "IGMP");
        break;
    case IPPROTO_TCP:
        snprintf(buffer + n, COLS + 1 - n, "%-10s", "TCP");
        break;
    case IPPROTO_UDP:
        print_udp(info, buffer, n);
        break;
    default:
        break;
    }
    print(buffer);
}

void print_udp(struct ip_info *info, char *buf, int n)
{
    if (info->udp.dns.qr == -1) {
        snprintf(buf + n, COLS + 1 - n, "%-10sSource port %d, destination port %d", "UDP", 
                 info->udp.src_port, info->udp.dst_port);
    } else {
        if (info->udp.dns.qr == 0) {
            switch (info->udp.dns.opcode) {
            case QUERY:
                snprintf(buf + n, COLS + 1 - n, "%-10sStandard query", "DNS");
                break;
            case IQUERY:
                snprintf(buf + n, COLS + 1 - n, "%-10sInverse query", "DNS");
                break;
            case STATUS:
                snprintf(buf + n, COLS + 1 - n, "%-10sServer status request", "DNS");
                break;
            }
        } else {
            switch (info->udp.dns.rcode) {
            case NO_ERROR:
                snprintf(buf + n, COLS + 1 - n, "%-10sResponse - no error", "DNS");
                break;
            case FORMAT_ERROR:
                snprintf(buf + n, COLS + 1 - n, "%-10sResponse - format error", "DNS");
                break;
            case SERVER_FAILURE:
                snprintf(buf + n, COLS + 1 - n, "%-10sResponse - server failure", "DNS");
                break;
            case NAME_ERROR:
                snprintf(buf + n, COLS + 1 - n, "%-10sResponse - name error", "DNS");
                break;
            case NOT_IMPLEMENTED:
                snprintf(buf + n, COLS + 1 - n, "%-10sResponse - request not supported", "DNS");
                break;
            case REFUSED:
                snprintf(buf + n, COLS + 1 - n, "%-10sResponse - operation refused", "DNS");
                break;
            }
        }
    }
}

/*
 * Get host name from addr, which is in dotted-decimal format. This will send a
 * DNS request over UDP.
 */
void gethost(char *addr, char *host, int hostlen)
{
    struct sockaddr_in saddr;
    struct in_addr naddr;
    int err;
    
    inet_pton(AF_INET, addr, &naddr);
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr = naddr;
    getnameinfo((struct sockaddr *) &saddr, sizeof(struct sockaddr_in),
                host, hostlen, NULL, 0, 0);
}
