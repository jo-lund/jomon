#include <arpa/inet.h>
#include <net/if_arp.h>
#include <string.h>
#include <linux/igmp.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include "misc.h"
#include "output.h"
#include "list.h"
#include "error.h"
#include "util.h"
#include "vector.h"

#define HEADER_HEIGHT 4
#define STATUS_HEIGHT 1
#define HOSTNAMELEN 255 /* maximum 255 according to rfc1035 */
#define ADDR_WIDTH 36
#define PROT_WIDTH 10
#define KEY_ESC 27
#define MAX_SELECTABLE 4
#define ETH_WINSIZE 4
#define ARP_WINSIZE 9
#define IP_WINSIZE 13
#define TCP_WINSIZE 10
#define UDP_WINSIZE 5
#define IGMP_WINSIZE 6

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define PRINT_ADDRESS(buffer, n, src, dst)                              \
    snprintf(buffer, n, "%-" STR(ADDR_WIDTH) "s" "%-" STR(ADDR_WIDTH) "s", src, dst)
#define PRINT_PROTOCOL(buffer, n, prot)                     \
    snprintcat(buffer, n, "%-" STR(PROT_WIDTH) "s", prot)
#define PRINT_INFO(buffer, n, fmt, ...)         \
    snprintcat(buffer, n, fmt, ## __VA_ARGS__)
#define PRINT_LINE(buffer, n, src, dst, prot, fmt, ...)   \
    do {                                                  \
        PRINT_ADDRESS(buffer, n, src, dst);               \
        PRINT_PROTOCOL(buffer, n, prot);                  \
        PRINT_INFO(buffer, n, fmt, ## __VA_ARGS__);       \
    } while (0)

struct subwin {
    int top;
    int bottom;
    WINDOW *wsub;
    bool selected[MAX_SELECTABLE];
};

struct line {
    bool selected;
    struct subwin win;
} *line_info;

static WINDOW *wheader;
static WINDOW *wmain;
static WINDOW *wstatus;
static int outy = 0;
static bool interactive = false;
static bool numeric = true;
static int selection_line = 0;
static int top = 0; /* index to top of screen */

/* the number of lines to be scrolled in order to print verbose packet information */
static int scrollvy = 0;

static void set_interactive(bool interactive_mode, int lines, int cols);
static bool check_line(int lines);
static void handle_keydown(int lines, int cols);
static void handle_keyup(int lines, int cols);
static void scroll_page(int lines, int cols);
static void scroll_window();
static void print_buffer(char *buf, int size, struct packet *p);
static int print_lines(int from, int to, int y, int cols);
static void print(char *buf);
static void print_header();
static void print_arp(char *buf, int n, struct arp_info *info);
static void print_ip(char *buf, int n, struct ip_info *info);
static void print_udp(char *buf, int n, struct ip_info *info);
static void print_tcp(char *buf, int n, struct ip_info *info);
static void print_icmp(char *buf, int n, struct ip_info *info);
static void print_igmp(char *buf, int n, struct ip_info *info);
static void print_dns(char *buf, int n, struct dns_info *dns);
static void print_nbns(char *buf, int n, struct nbns_info *nbns);
static void print_ssdp(char *buf, int n, list_t *ssdp);
static void print_http(char *buf, int n, struct http_info *http);
static void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type, bool *soa);
static void print_nbns_record(struct nbns_info *info, int i, char *buf, int n, uint16_t type);

/* Print verbose packet information in a subwindow */
static void create_subwindow(int num_lines, int lineno);
static void delete_subwindow();
static bool update_subwin_selection(int lineno);
static int calculate_subwin_size(struct packet *p, int screen_line);
static int calculate_applayer_size(struct application_info *info, int screen_line);
static void print_information();
static void print_protocol_information(struct packet *p, int lineno);
static void print_ethernet_verbose(struct packet *p, int lineno, int y);
static void print_arp_verbose(struct packet *p, int lineno, int y);
static void print_ip_verbose(struct ip_info *ip, int lineno, int y);
static void print_udp_verbose(struct ip_info *ip, int lineno, int y);
static void print_tcp_verbose(struct ip_info *ip, int lineno, int y);
static void print_app_protocol(struct application_info *info, int lineno, int y);
static void print_dns_verbose(struct dns_info *dns, int lineno, int y);
static void print_dns_soa(struct dns_info *info, int i, int lineno, int y, int x);
static void print_nbns_verbose(struct nbns_info *nbns, int lineno, int y);
static void print_icmp_verbose(struct ip_info *ip, int lineno, int y);
static void print_igmp_verbose(struct ip_info *info, int lineno, int y);
static void print_ssdp_verbose(list_t *ssdp, int lineno, int y);
static void print_http_verbose(struct http_info *http);

void init_ncurses()
{
    initscr(); /* initialize curses mode */
    cbreak(); /* disable line buffering */
    noecho();
    curs_set(0); /* make the cursor invisible */
    use_default_colors();
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_CYAN);
    set_escdelay(25); /* set escdelay to 25 ms */
}

void end_ncurses()
{
    endwin(); /* end curses mode */
    free(line_info);
}

void create_layout()
{
    int mx, my;

    getmaxyx(stdscr, my, mx);
    wheader = newwin(HEADER_HEIGHT, mx, 0, 0);
    wmain = newwin(my - HEADER_HEIGHT - STATUS_HEIGHT, mx, HEADER_HEIGHT, 0);
    wstatus = newwin(STATUS_HEIGHT, mx, my - STATUS_HEIGHT, 0);
    nodelay(wmain, TRUE); /* input functions must be non-blocking */
    keypad(wmain, TRUE);
    print_header();
    scrollok(wmain, TRUE); /* enable scrolling */
    line_info = calloc(my, sizeof(struct line));
}

/* scroll the window if necessary */
void scroll_window()
{
    int my;

    my = getmaxy(wmain);
    if (outy >= my) {
        outy = my - 1;
        scroll(wmain);
        top++;
    }
}

void get_input()
{
    int c = 0;
    int mx, my;

    getmaxyx(wmain, my, mx);
    c = wgetch(wmain);
    switch (c) {
    case 'i':
        set_interactive(!interactive, my, mx);
        break;
    case 'q':
        kill(0, SIGINT);
        break;
    case 'n':
        numeric = !numeric;
        break;
    case KEY_UP:
        handle_keyup(my, mx);
        break;
    case KEY_DOWN:
        handle_keydown(my, mx);
        break;
    case KEY_ENTER:
    case '\n':
        if (interactive) {
            print_information();
        }
        break;
    case KEY_ESC:
        if (interactive) {
            set_interactive(false, my, mx);
        }
        break;
    case ' ':
    case KEY_NPAGE:
        scroll_page(my, mx);
        break;
    case 'b':
    case KEY_PPAGE:
        scroll_page(-my, mx);
        break;
    default:
        break;
    }
}

/*
 * Checks if there still are lines to highlight when moving the selection bar
 * down. Returns true if that's the case.
 */
bool check_line(int lines)
{
    int num_lines = 0;

    for (int i = 0; i < lines; i++) {
        if (line_info[i].win.wsub) {
            num_lines += (line_info[i].win.bottom - line_info[i].win.top + 1);
        }
    }
    if (selection_line < vector_size() + num_lines - 1) return true;

    return false;
}

void handle_keyup(int lines, int cols)
{
    if (!interactive) {
        set_interactive(true, lines, cols);
    }

    /* scroll screen if the selection bar is at the top */
    if (top && selection_line == top) {
        struct packet *p = vector_get_data(--selection_line);

        top--;
        if (p) {
            char line[cols];

            wscrl(wmain, -1);
            print_buffer(line, cols, p);
            mvwprintw(wmain, 0, 0, "%s", line);

            /* deselect previous line and highlight next at top */
            mvwchgat(wmain, 1, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain, 0, 0, -1, A_NORMAL, 1, NULL);
        }
    } else if (selection_line > 0) {
         int screen_line = selection_line - top;

        /* deselect previous line and highlight next */
        mvwchgat(wmain, screen_line, 0, -1, A_NORMAL, 0, NULL);
        mvwchgat(wmain, screen_line - 1, 0, -1, A_NORMAL, 1, NULL);
        selection_line--;
    }
    wrefresh(wmain);
}

void handle_keydown(int lines, int cols)
{
    if (!check_line(lines)) return;

    if (!interactive) {
        set_interactive(true, lines, cols);
    }

    /* scroll screen if the selection bar is at the bottom */
    if (selection_line - top == lines - 1) {
        struct packet *p = vector_get_data(++selection_line);

        top++;
        if (p) {
            char line[cols];

            wscrl(wmain, 1);
            print_buffer(line, cols, p);
            mvwprintw(wmain, lines - 1, 0, "%s", line);

            /* deselect previous line and highlight next line at bottom */
            mvwchgat(wmain, lines - 2, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain, lines - 1, 0, -1, A_NORMAL, 1, NULL);
        }
    } else {
        int screen_line = selection_line - top;

        /* deselect previous line and highlight next */
        mvwchgat(wmain, screen_line, 0, -1, A_NORMAL, 0, NULL);
        mvwchgat(wmain, screen_line + 1, 0, -1, A_NORMAL, 1, NULL);
        selection_line++;
    }
    wrefresh(wmain);
}

void scroll_page(int lines, int cols)
{
    if (lines > 0) { /* scroll page down */
        if (vector_size() <= lines) {
            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 0, NULL);
            selection_line = vector_size() - 1;
            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 1, NULL);
        } else {
            int bottom = top + lines - 1;

            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 0, NULL);
            selection_line += lines;
            if (bottom + lines > vector_size() - 1) {
                int scroll = vector_size() - bottom - 1;

                wscrl(wmain, scroll);
                top += scroll;
                if (selection_line >= vector_size()) {
                    selection_line = vector_size() - 1;
                }
                print_lines(bottom + 1, vector_size(), vector_size() - scroll - top, cols);
            } else {
                top += lines;
                wscrl(wmain, lines);
                print_lines(top, top + lines, 0, cols);
            }
            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 1, NULL);
        }
    } else { /* scroll page up */
        if (vector_size() <= abs(lines)) {
            mvwchgat(wmain, selection_line, 0, -1, A_NORMAL, 0, NULL);
            selection_line = 0;
            mvwchgat(wmain, 0, 0, -1, A_NORMAL, 1, NULL);
        } else {
            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 0, NULL);
            selection_line += lines;
            if (top + lines < 0) {
                wscrl(wmain, -top);
                top = 0;
                if (selection_line < 0) {
                    selection_line = 0;
                }
                print_lines(top, top - lines, 0, cols);
            } else {
                wscrl(wmain, lines);
                top += lines;
                print_lines(top, top - lines, 0, cols);
            }
            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 1, NULL);
        }
    }
    wrefresh(wmain);
}

void set_interactive(bool interactive_mode, int lines, int cols)
{
    if (!vector_size()) return;

    if (interactive_mode) {
        interactive = true;
        mvwprintw(wstatus, 0, 0, "(interactive)");
        wrefresh(wstatus);
        selection_line = top;

        /* print selection bar */
        mvwchgat(wmain, 0, 0, -1, A_NORMAL, 1, NULL);
        wrefresh(wmain);
    } else {
        if (outy >= lines) {
            int c = vector_size() - 1;

            werase(wmain);

            /* print the new lines stored in vector from bottom to top of screen */
            for (int i = lines - 1; i >= 0; i--, c--) {
                struct packet *p;
                char buffer[cols];

                p = vector_get_data(c);
                print_buffer(buffer, cols, p);
                mvwprintw(wmain, i, 0, "%s", buffer);
            }
            top = c + 1;
        } else {
            /* remove selection bar */
            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 0, NULL);
        }
        interactive = false;
        wrefresh(wmain);
        werase(wstatus);
        wrefresh(wstatus);
    }
}

/*
 * Prints lines in the interval [from, to). 'y' specifies where on the screen it
 * will start to print. Returns how many lines are actually printed.
 */
int print_lines(int from, int to, int y, int cols)
{
    int c = 0;

    while (from < to) {
        struct packet *p;
        char buffer[cols];

        p = vector_get_data(from);
        if (!p) break;
        print_buffer(buffer, cols, p);
        mvwprintw(wmain, y++, 0, "%s", buffer);
        from++;
        c++;
    }
    return c;
}

void print_header()
{
    int y = 0;
    char addr[INET_ADDRSTRLEN];

    mvwprintw(wheader, y, 0, "Listening on device: %s", device);
    inet_ntop(AF_INET, &local_addr->sin_addr, addr, sizeof(addr));
    mvwprintw(wheader, ++y, 0, "Local address: %s", addr);
    y += 2;
    if (statistics) {
        attron(A_BOLD);
        mvwprintw(wheader, y, 0, "RX:");
        mvwprintw(wheader, ++y, 0, "TX:");
        attroff(A_BOLD);
    } else {
        mvwprintw(wheader, y, 0, "Source");
        mvwprintw(wheader, y, ADDR_WIDTH, "Destination");
        mvwprintw(wheader, y, 2 * ADDR_WIDTH, "Protocol");
        mvwprintw(wheader, y, 2 * ADDR_WIDTH + PROT_WIDTH, "Info");
        mvwchgat(wheader, y, 0, -1, A_STANDOUT, 0, NULL);
    }
    wrefresh(wheader);
}

void print_packet(struct packet *p)
{
    int mx = getmaxx(wmain);
    char buf[mx];

    print_buffer(buf, mx, p);
    print(buf);
}

/* write packet to buffer */
void print_buffer(char *buf, int size, struct packet *p)
{
    switch (p->eth.ethertype) {
    case ETH_P_ARP:
        print_arp(buf, size, p->eth.arp);
        break;
    case ETH_P_IP:
        print_ip(buf, size, p->eth.ip);
        break;
    default:
        break;
    }
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

/* write buffer to standard output */
void print(char *buf)
{
    int my;

    my = getmaxy(wmain);
    if (!interactive || (interactive && outy < my)) {
        scroll_window();
        mvwprintw(wmain, outy, 0, "%s", buf);
        outy++;
        wrefresh(wmain);
    }
}

/* print ARP frame information */
void print_arp(char *buf, int n, struct arp_info *info)
{
    switch (info->op) {
    case ARPOP_REQUEST:
        PRINT_LINE(buf, n, info->sip, info->tip, "ARP",
                   "Request: Looking for hardware address of %s", info->tip);
        break;
    case ARPOP_REPLY:
        PRINT_LINE(buf, n, info->sip, info->tip, "ARP",
                   "Reply: %s has hardware address %s", info->sip, info->sha);
        break;
    default:
        PRINT_LINE(buf, n, info->sip, info->tip, "ARP", "Opcode %d", info->op);
        break;
    }
}

/* print IP packet information */
void print_ip(char *buf, int n, struct ip_info *info)
{
    if (!numeric && (info->protocol != IPPROTO_UDP ||
                     (info->protocol == IPPROTO_UDP && info->udp.data.dns->qr == -1))) {
        char sname[HOSTNAMELEN];
        char dname[HOSTNAMELEN];

        /* get the host name of source and destination */
        gethost(info->src, sname, HOSTNAMELEN);
        gethost(info->dst, dname, HOSTNAMELEN);
        // TEMP: Fix this!
        sname[35] = '\0';
        dname[35] = '\0';
        PRINT_ADDRESS(buf, n, sname, dname);
    } else {
        PRINT_ADDRESS(buf, n, info->src, info->dst);
    }
    switch (info->protocol) {
    case IPPROTO_ICMP:
        print_icmp(buf, n, info);
        break;
    case IPPROTO_IGMP:
        print_igmp(buf, n, info);
        break;
    case IPPROTO_TCP:
        print_tcp(buf, n, info);
        break;
    case IPPROTO_UDP:
        print_udp(buf, n, info);
        break;
    default:
        break;
    }
}

void print_icmp(char *buf, int n, struct ip_info *info)
{
    PRINT_PROTOCOL(buf, n, "ICMP");
    switch (info->icmp.type) {
    case ICMP_ECHOREPLY:
        PRINT_INFO(buf, n, "Echo reply:   id = 0x%x  seq = %d", info->icmp.echo.id, info->icmp.echo.seq_num);
        break;
    case ICMP_ECHO:
        PRINT_INFO(buf, n, "Echo request: id = 0x%x  seq = %d", info->icmp.echo.id, info->icmp.echo.seq_num);
        break;
    case ICMP_DEST_UNREACH:
        PRINT_INFO(buf, n, "%s", get_icmp_dest_unreach_code(info->icmp.code));
        break;
    default:
        PRINT_INFO(buf, n, "Type: %d", info->icmp.type);
        break;
    }
}

void print_igmp(char *buf, int n, struct ip_info *info)
{
    PRINT_PROTOCOL(buf, n, "IGMP");
    switch (info->igmp.type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        PRINT_INFO(buf, n, "Membership query  Max response time: %d seconds",
                        info->igmp.max_resp_time / 10);
        break;
    case IGMP_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "Membership report");
        break;
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "IGMP2 Membership report");
        break;
    case IGMP_HOST_LEAVE_MESSAGE:
        PRINT_INFO(buf, n, "Leave group");
        break;
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "IGMP3 Membership report");
        break;
    default:
        PRINT_INFO(buf, n, "Type 0x%x", info->igmp.type);
        break;
    }
    PRINT_INFO(buf, n, "  Group address: %s", info->igmp.group_addr);
}

void print_tcp(char *buf, int n, struct ip_info *info)
{
    switch (info->tcp.data.utype) {
    case HTTP:
        print_http(buf, n, info->tcp.data.http);
        break;
    case DNS:
        print_dns(buf, n, info->tcp.data.dns);
        break;
    case NBNS:
        print_nbns(buf, n, info->tcp.data.nbns);
        break;
    default:
        PRINT_PROTOCOL(buf, n, "TCP");
        PRINT_INFO(buf, n, "Source port: %d  Destination port: %d", info->tcp.src_port,
                   info->tcp.dst_port);
        PRINT_INFO(buf, n, "  Flags: ");
        if (info->tcp.urg) {
            PRINT_INFO(buf, n, "URG ");
        }
        if (info->tcp.ack) {
            PRINT_INFO(buf, n, "ACK ");
        }
        if (info->tcp.psh) {
            PRINT_INFO(buf, n, "PSH ");
        }
        if (info->tcp.rst) {
            PRINT_INFO(buf, n, "RST ");
        }
        if (info->tcp.syn) {
            PRINT_INFO(buf, n, "SYN ");
        }
        if (info->tcp.fin) {
            PRINT_INFO(buf, n, "FIN");
        }
        break;
    }
}

void print_udp(char *buf, int n, struct ip_info *info)
{
    switch (info->udp.data.utype) {
    case DNS:
        print_dns(buf, n, info->udp.data.dns);
        break;
    case NBNS:
        print_nbns(buf, n, info->udp.data.nbns);
        break;
    case SSDP:
        print_ssdp(buf, n, info->udp.data.ssdp);
        break;
    default:
        PRINT_PROTOCOL(buf, n, "UDP");
        PRINT_INFO(buf, n, "Source port: %d  Destination port: %d", info->udp.src_port,
                   info->udp.dst_port);
        break;
    }
}

void print_dns(char *buf, int n, struct dns_info *dns)
{
    PRINT_PROTOCOL(buf, n, "DNS");
    if (dns->qr == 0) {
        switch (dns->opcode) {
        case DNS_QUERY:
            PRINT_INFO(buf, n, "Standard query: ");
            PRINT_INFO(buf, n, "%s ", dns->question.qname);
            PRINT_INFO(buf, n, "%s ", get_dns_class(dns->question.qclass));
            PRINT_INFO(buf, n, "%s", get_dns_type(dns->question.qtype));
            break;
        case DNS_IQUERY:
            PRINT_INFO(buf, n, "Inverse query");
            break;
        case DNS_STATUS:
            PRINT_INFO(buf, n, "Server status request");
            break;
        }
    } else {
        switch (dns->rcode) {
        case DNS_FORMAT_ERROR:
            PRINT_INFO(buf, n, "Response: format error");
            return;
        case DNS_SERVER_FAILURE:
            PRINT_INFO(buf, n, "Response: server failure");
            return;
        case DNS_NAME_ERROR:
            PRINT_INFO(buf, n, "Response: name error");
            return;
        case DNS_NOT_IMPLEMENTED:
            PRINT_INFO(buf, n, "Response: request not supported");
            return;
        case DNS_REFUSED:
            PRINT_INFO(buf, n, "Response: operation refused");
            return;
        case DNS_NO_ERROR:
        default:
            PRINT_INFO(buf, n, "Response: ");
            break;
        }
        // TODO: Need to print the proper name for all values.
        PRINT_INFO(buf, n, "%s ", dns->record[0].name);
        PRINT_INFO(buf, n, "%s ", get_dns_class(dns->record[0].class));
        PRINT_INFO(buf, n, "%s ", get_dns_type(dns->record[0].type));
        for (int i = 0; i < dns->section_count[ANCOUNT]; i++) {
            print_dns_record(dns, i, buf, n, dns->record[i].type, NULL);
            PRINT_INFO(buf, n, " ");
        }
    }
}

void print_nbns(char *buf, int n, struct nbns_info *nbns)
{
    PRINT_PROTOCOL(buf, n, "NBNS");
    if (nbns->r == 0) {
        char opcode[16];

        strncpy(opcode, get_nbns_opcode(nbns->opcode), sizeof(opcode));
        PRINT_INFO(buf, n, "Name %s request: ", strtolower(opcode));
        PRINT_INFO(buf, n, "%s ", nbns->question.qname);
        PRINT_INFO(buf, n, "%s ", get_nbns_type(nbns->question.qtype));
        if (nbns->section_count[ARCOUNT]) {
            print_nbns_record(nbns, 0, buf, n, nbns->record[0].rrtype);
        }
    } else {
        switch (nbns->rcode) {
        case NBNS_FMT_ERR:
            PRINT_INFO(buf, n, "Format Error. Request was invalidly formatted");
            return;
        case NBNS_SRV_ERR:
            PRINT_INFO(buf, n, "Server failure. Problem with NBNS, cannot process name");
            return;
        case NBNS_IMP_ERR:
            PRINT_INFO(buf, n, "Unsupported request error");
            return;
        case NBNS_RFS_ERR:
            PRINT_INFO(buf, n, "Refused error");
            return;
        case NBNS_ACT_ERR:
            PRINT_INFO(buf, n, "Active error. Name is owned by another node");
            return;
        case NBNS_CFT_ERR:
            PRINT_INFO(buf, n, "Name in conflict error");
            return;
        default:
            break;
        }
        char opcode[16];

        strncpy(opcode, get_nbns_opcode(nbns->opcode), sizeof(opcode));
        PRINT_INFO(buf, n, "Name %s response: ", strtolower(opcode));
        PRINT_INFO(buf, n, "%s ", nbns->record[0].rrname);
        PRINT_INFO(buf, n, "%s ", get_nbns_type(nbns->record[0].rrtype));
        print_nbns_record(nbns, 0, buf, n, nbns->record[0].rrtype);
    }
}

void print_ssdp(char *buf, int n, list_t *ssdp)
{
    const node_t *node;

    PRINT_PROTOCOL(buf, n, "SSDP");
    node = list_begin(ssdp);
    if (node) {
        PRINT_INFO(buf, n, (char *) list_data(node));
    }
}

void print_http(char *buf, int n, struct http_info *http)
{
    PRINT_PROTOCOL(buf, n, "HTTP");
    PRINT_INFO(buf, n, "%s", http->start_line);
}

void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type, bool *soa)
{
    switch (type) {
    case DNS_TYPE_A:
    {
        char addr[INET_ADDRSTRLEN];
        uint32_t haddr = htonl(info->record[i].rdata.address);

        inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr));
        snprintcat(buf, n, "%s", addr);
        break;
    }
    case DNS_TYPE_NS:
        snprintcat(buf, n, "%s", info->record[i].rdata.nsdname);
        break;
    case DNS_TYPE_SOA:
        if (soa) *soa = true;
        break;
    case DNS_TYPE_CNAME:
        snprintcat(buf, n, "%s", info->record[i].rdata.cname);
        break;
    case DNS_TYPE_PTR:
        snprintcat(buf, n, "%s", info->record[i].rdata.ptrdname);
        break;
    case DNS_TYPE_AAAA:
    {
        char addr[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, (struct in_addr *) info->record[i].rdata.ipv6addr, addr, sizeof(addr));
        snprintcat(buf, n, "%s", addr);
        break;
    }
    default:
        break;
    }
}

void print_nbns_record(struct nbns_info *info, int i, char *buf, int n, uint16_t type)
{
    switch (info->record[i].rrtype) {
    case NBNS_NB:
    {
        if (info->record[i].rdata.nb.g) {
            snprintcat(buf, n, "Group NetBIOS name ");
        } else {
            snprintcat(buf, n, "Unique NetBIOS name ");
        }
        int addrs = info->record[i].rdata.nb.num_addr;
        snprintcat(buf, n, "%s ", get_nbns_node_type(info->record[i].rdata.nb.ont));
        while (addrs--) {
            char addr[INET_ADDRSTRLEN];
            uint32_t haddr = htonl(info->record[i].rdata.nb.address[0]);

            inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr));
            snprintcat(buf, n, "%s ", addr);
        }
        break;
    }
    case NBNS_NS:
        snprintcat(buf, n, " NSD Name: %s", info->record[i].rdata.nsdname);
        break;
    case NBNS_A:
    {
        char addr[INET_ADDRSTRLEN];
        uint32_t haddr = htonl(info->record[i].rdata.nsdipaddr);

        inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr));
        snprintcat(buf, n, " NSD IP address: %s", addr);
        break;
    }
    case NBNS_NBSTAT:
        snprintcat(buf, n, "NBSTAT");
        break;
    default:
        break;
    }
}

void create_subwindow(int num_lines, int lineno)
{
    int mx, my;
    int start_line;
    int c;

    getmaxyx(wmain, my, mx);
    start_line = lineno - top;
    c = lineno + 1;

    /* if there is not enough space for the information to be printed, the
        screen needs to be scrolled to make room for all the lines */
    if (my - (start_line + 1) < num_lines) {
        scrollvy = num_lines - (my - (start_line + 1));
        wscrl(wmain, scrollvy);
        start_line -= scrollvy;
        selection_line -= scrollvy;
        wrefresh(wmain);
    }

    /* make space for protocol specific information */
    line_info[start_line].win.wsub = derwin(wmain, num_lines, mx, start_line + 1, 0);
    line_info[start_line].win.top = start_line + 1;
    line_info[start_line].win.bottom = line_info[start_line].win.top + num_lines - 1;
    wmove(wmain, start_line + 1, 0);
    wclrtobot(wmain); /* clear everything below selection bar */
    outy = start_line + num_lines + 1;

    if (!scrollvy) {
        outy += print_lines(c, top + my, outy, mx);
    }
    wrefresh(wmain);
}

void delete_subwindow()
{
    int my, mx;
    int screen_line;

    getmaxyx(wmain, my, mx);
    screen_line = selection_line - top;
    delwin(line_info[screen_line].win.wsub);
    memset(&line_info[screen_line].win, 0, sizeof(struct subwin));
    werase(wmain);

    /*
     * Print the entire screen. This can be optimized to just print the lines
     * that are below the selected line
     */
    outy = print_lines(top, top + my, 0, mx);

    if (scrollvy) {
        screen_line += scrollvy;
        selection_line += scrollvy;
        scrollvy = 0;
    }
    mvwchgat(wmain, screen_line, 0, -1, A_NORMAL, 1, NULL);
    wrefresh(wmain);
}

/*
 * Print more information about a packet when selected. This will print more
 * details about the specific protocol headers and payload.
 */
void print_information()
{
    int screen_line;
    struct packet *p;
    static int prev_selection = -1;

    if (prev_selection >= 0) {
        screen_line = prev_selection - top;
        if (line_info[screen_line].win.wsub) {
            bool inside_subwin;

            inside_subwin = update_subwin_selection(prev_selection);
            if (inside_subwin) {
                p = vector_get_data(prev_selection);
                print_protocol_information(p, prev_selection);
                return;
            }
        }
    }
    screen_line = selection_line - top;
    line_info[screen_line].selected = !line_info[screen_line].selected;
    if (line_info[screen_line].selected) {
        p = vector_get_data(selection_line);
        print_protocol_information(p, selection_line);
    } else {
        delete_subwindow();
    }
    prev_selection = selection_line;
}

/*
 * Checks if selection_line is inside the subwindow, and if that's the case, updates the
 * selection status of the selectable subwindow line.
 *
 * Returns true if it's inside the subwindow, else false.
 * TODO: How to update the subwindow's selectable elements when there are some
 * elements that are already selected?
 */
bool update_subwin_selection(int lineno)
{
    int screen_line;
    int sub_start_line;

    screen_line = selection_line - top;
    sub_start_line = lineno - top;
    if (screen_line >= line_info[sub_start_line].win.top &&
        screen_line <= line_info[sub_start_line].win.bottom) {
        int subline;
        
        subline = screen_line - line_info[sub_start_line].win.top;
        if (subline < MAX_SELECTABLE) {
            line_info[sub_start_line].win.selected[subline] = !line_info[sub_start_line].win.selected[subline];
        }
        return true;
    }
    return false;
}

/* Calculates size of subwindow */
int calculate_subwin_size(struct packet *p, int screen_line)
{
    int size = 1;
 
    if (line_info[screen_line].win.selected[0]) {
        size += ETH_WINSIZE + 1;
    } else {
        size++;
    }
    if (p->eth.ethertype == ETH_P_ARP) {
        if (line_info[screen_line].win.selected[1]) {
            size += ARP_WINSIZE;
        } else {
            size++;
        }
    } else if (p->eth.ethertype == ETH_P_IP) {
        if (line_info[screen_line].win.selected[1]) {
            size += IP_WINSIZE + 1;
        } else {
            size++;
        }
        switch (p->eth.ip->protocol) {
        case IPPROTO_TCP:
            if (line_info[screen_line].win.selected[2]) {
                size += TCP_WINSIZE;
            }
            size += calculate_applayer_size(&p->eth.ip->tcp.data, screen_line);
            break;
        case IPPROTO_UDP:
            if (line_info[screen_line].win.selected[2]) {
                size += UDP_WINSIZE;
            }
            size += calculate_applayer_size(&p->eth.ip->udp.data, screen_line);
            break;
        case IPPROTO_ICMP:
            if (line_info[screen_line].win.selected[2]) {
                if (p->eth.ip->icmp.type == ICMP_ECHOREPLY ||
                    p->eth.ip->icmp.type == ICMP_ECHO) {
                    size += 7;
                } else {
                    size += 5;
                }
            } else {
                size++;
            }
            break;
        case IPPROTO_IGMP:
            if (line_info[screen_line].win.selected[2]) {
                size += IGMP_WINSIZE;
            } else {
                size++;
            }
            break;
        default:
            break;
        }
    }
    return size;
}

int calculate_applayer_size(struct application_info *info, int screen_line)
{
    int size = 1;

    if (line_info[screen_line].win.selected[3]) {
        switch (info->utype) {
        case DNS:
        {
            int records = 0;
            
            /* number of resource records */
            for (int i = 1; i < 4; i++) {
                records += info->dns->section_count[i];
            }
            size += (info->dns->section_count[NSCOUNT] ? 18 + records : 10 + records);
            break;
        }
        case NBNS:
        {
            int records = 0;

            /* number of resource records */
            for (int i = 1; i < 4; i++) {
                records += info->nbns->section_count[i];
            }
            size += (records ? 11 + records : 10);
            break;
        }
        case HTTP:
            break;
        case SSDP:
            size += list_size(info->ssdp) + 2;
            break;
        default:
            break;
        }
    } else {
        size++;
    }
    return size;
}

void print_protocol_information(struct packet *p, int lineno)
{
    int screen_line = lineno - top;
    int size = 0;
    int y = 0;

    size = calculate_subwin_size(p, lineno);

    /* Delete old subwindow. TODO: Possible to just resize? */
    if (line_info[screen_line].win.wsub) {
        delete_subwindow(lineno);
    }

    /* print information in subwindow */
    create_subwindow(size, lineno);
    if (line_info[screen_line].win.selected[0]) {
        mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- Ethernet header");
        print_ethernet_verbose(p, lineno, y);
        y += ETH_WINSIZE;
    } else {
        mvwprintw(line_info[screen_line].win.wsub, y++, 2, "+ Ethernet header");
    }
    if (p->eth.ethertype == ETH_P_ARP) {
        if (line_info[screen_line].win.selected[1]) {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- ARP header");
            print_arp_verbose(p, lineno, y);
        } else {
            mvwprintw(line_info[screen_line].win.wsub, y, 2, "+ ARP header");
        }
    } else if (p->eth.ethertype == ETH_P_IP) {
        if (line_info[screen_line].win.selected[1]) {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- IP header");
            print_ip_verbose(p->eth.ip, lineno, y);
            y += IP_WINSIZE;
        } else {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "+ IP header");
        }
        switch (p->eth.ip->protocol) {
        case IPPROTO_TCP:
            if (line_info[screen_line].win.selected[2]) {
                mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- TCP header");
                print_tcp_verbose(p->eth.ip, lineno, y);
                y += TCP_WINSIZE;
            } else {
                mvwprintw(line_info[screen_line].win.wsub, y++, 2, "+ TCP header");
            }
            print_app_protocol(&p->eth.ip->tcp.data, lineno, y);
            break;
        case IPPROTO_UDP:
            if (line_info[screen_line].win.selected[2]) {
                mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- UDP header");
                print_udp_verbose(p->eth.ip, lineno, y);
                y += UDP_WINSIZE;
            } else {
                mvwprintw(line_info[screen_line].win.wsub, y++, 2, "+ UDP header");
            }
            print_app_protocol(&p->eth.ip->udp.data, lineno, y);
            break;
        case IPPROTO_ICMP:
            if (line_info[screen_line].win.selected[2]) {
                mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- ICMP header");
                print_icmp_verbose(p->eth.ip, lineno, y);
            } else {
                mvwprintw(line_info[screen_line].win.wsub, y++, 2, "+ ICMP header");
            }
            break;
        case IPPROTO_IGMP:
            if (line_info[screen_line].win.selected[2]) {
                mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- IGMP header");
                print_igmp_verbose(p->eth.ip, lineno, y);
            } else {
                mvwprintw(line_info[screen_line].win.wsub, y++, 2, "+ IGMP header");
            }
            break;
        }        
    }
    mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 1, NULL);
    touchwin(wmain);
    wrefresh(line_info[screen_line].win.wsub);
}


void print_app_protocol(struct application_info *info, int lineno, int y)
{
    int screen_line = lineno - top;

    switch (info->utype) {
    case DNS:
        if (line_info[screen_line].win.selected[3]) {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- DNS header");
            print_dns_verbose(info->dns, lineno, y);
        } else {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "+ DNS header");
        }
        break;
    case NBNS:
        if (line_info[screen_line].win.selected[3]) {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- NBNS header");
            print_nbns_verbose(info->nbns, lineno, y);
        } else {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "+ NBNS header");
        }
        break;
    case SSDP:
        if (line_info[screen_line].win.selected[3]) {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- SSDP header");
            print_ssdp_verbose(info->ssdp, lineno, y);
        } else {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "+ SSDP header");
        }
        break;
    case HTTP:
        if (line_info[screen_line].win.selected[3]) {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "- HTTP header");
            print_http_verbose(info->http);
        } else {
            mvwprintw(line_info[screen_line].win.wsub, y++, 2, "+ HTTP header");
        }
        break;
    default:
        break;
    }
}

void print_ethernet_verbose(struct packet *p, int lineno, int y)
{
    int screen_line = lineno - top;
    char src[HW_ADDRSTRLEN];
    char dst[HW_ADDRSTRLEN];

    snprintf(src, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             p->eth.mac_src[0], p->eth.mac_src[1], p->eth.mac_src[2],
             p->eth.mac_src[3], p->eth.mac_src[4], p->eth.mac_src[5]);
    snprintf(dst, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             p->eth.mac_dst[0], p->eth.mac_dst[1], p->eth.mac_dst[2],
             p->eth.mac_dst[3], p->eth.mac_dst[4], p->eth.mac_dst[5]);
    mvwprintw(line_info[screen_line].win.wsub, y, 4, "MAC source: %s", src);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "MAC destination: %s", dst);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Ethertype: 0x%x", p->eth.ethertype);
}

void print_arp_verbose(struct packet *p, int lineno, int y)
{
    int screen_line = lineno - top;

    mvwprintw(line_info[screen_line].win.wsub, y, 4, "Hardware type: %d (%s)", p->eth.arp->ht, get_arp_hardware_type(p->eth.arp->ht));
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Protocol type: 0x%x (%s)", p->eth.arp->pt, get_arp_protocol_type(p->eth.arp->pt));
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Hardware size: %d", p->eth.arp->hs);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Protocol size: %d", p->eth.arp->ps);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Opcode: %d (%s)", p->eth.arp->op, get_arp_opcode(p->eth.arp->op));
    mvwprintw(line_info[screen_line].win.wsub, ++y, 0, "");
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Sender IP: %-15s  HW: %s", p->eth.arp->sip, p->eth.arp->sha);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Target IP: %-15s  HW: %s", p->eth.arp->tip, p->eth.arp->tha);
}

void print_ip_verbose(struct ip_info *ip, int lineno, int y)
{
    int screen_line = lineno - top;

    mvwprintw(line_info[screen_line].win.wsub, y, 4, "Version: %u", ip->version);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Internet Header Length (IHL): %u", ip->ihl);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Differentiated Services Code Point (DSCP): %u", ip->dscp);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Explicit Congestion Notification (ECN): %u", ip->ecn);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Total length: %u", ip->length);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Identification: %u", ip->id);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Flags: %u%u%u", ip->foffset & 0x80, ip->foffset & 0x40, ip->foffset & 0x20);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Time to live: %u", ip->ttl);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Protocol: %u", ip->protocol);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Checksum: %u", ip->checksum);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Source IP address: %s", ip->src);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Destination IP address: %s", ip->dst);
}

void print_icmp_verbose(struct ip_info *ip, int lineno, int y)
{
    int screen_line = lineno - top;

    mvwprintw(line_info[screen_line].win.wsub, y, 4, "Type: %d (%s)", ip->icmp.type, get_icmp_type(ip->icmp.type));
    switch (ip->icmp.type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Code: %d", ip->icmp.code);
        break;
    case ICMP_DEST_UNREACH:
        mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Code: %d (%s)", ip->icmp.code, get_icmp_dest_unreach_code(ip->icmp.code));
        break;
    default:
        break;
    }
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Checksum: %d", ip->icmp.checksum);
    if (ip->icmp.type == ICMP_ECHOREPLY || ip->icmp.type == ICMP_ECHO) {
        mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Identifier: 0x%x", ip->icmp.echo.id);
        mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Sequence number: %d", ip->icmp.echo.seq_num);
    }
}

void print_igmp_verbose(struct ip_info *info, int lineno, int y)
{
    int screen_line = lineno - top;

    mvwprintw(line_info[screen_line].win.wsub, y, 4, "Type: %d (%s) ", info->igmp.type, get_igmp_type(info->icmp.type));
    if (info->igmp.type == IGMP_HOST_MEMBERSHIP_QUERY) {
        if (!strcmp(info->igmp.group_addr, "0.0.0.0")) {
            mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "General query", info->igmp.type, get_igmp_type(info->icmp.type));
        } else {
            mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Group-specific query", info->igmp.type, get_igmp_type(info->icmp.type));
        }
    }
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Max response time: %d seconds", info->igmp.max_resp_time / 10);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Checksum: %d", info->igmp.checksum);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Group address: %s", info->igmp.group_addr);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 0, "");
}

void print_udp_verbose(struct ip_info *ip, int lineno, int y)
{
    int screen_line = lineno - top;
    
    mvwprintw(line_info[screen_line].win.wsub, y, 4, "Source port: %u", ip->udp.src_port);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Destination port: %u", ip->udp.dst_port);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Length: %u", ip->udp.len);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Checksum: %u", ip->udp.checksum);
}

void print_tcp_verbose(struct ip_info *ip, int lineno, int y)
{
    int screen_line = lineno - top;
    
    mvwprintw(line_info[screen_line].win.wsub, y, 4, "Source port: %u", ip->tcp.src_port);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Destination port: %u", ip->tcp.dst_port);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Sequence number: %u", ip->tcp.seq_num);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Acknowledgment number: %u", ip->tcp.ack_num);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Data offset: %u", ip->tcp.offset);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Flags: %u%u%u%u%u%u%u%u%u",
              ip->tcp.ns, ip->tcp.cwr, ip->tcp.ece, ip->tcp.urg, ip->tcp.ack,
              ip->tcp.psh, ip->tcp.rst, ip->tcp.syn, ip->tcp.fin);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Window size: %u", ip->tcp.window);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Checksum: %u", ip->tcp.checksum);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Urgent pointer: %u", ip->tcp.urg_ptr);
}

void print_dns_verbose(struct dns_info *dns, int lineno, int y)
{
    int records = 0;
    int screen_line = lineno - top;

    /* number of resource records */
    for (int i = 1; i < 4; i++) {
        records += dns->section_count[i];
    }
    mvwprintw(line_info[screen_line].win.wsub, y, 4, "ID: 0x%x", dns->id);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "QR: %d (%s)", dns->qr, dns->qr ? "DNS Response" : "DNS Query");
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Opcode: %d (%s)", dns->opcode, get_dns_opcode(dns->opcode));
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Flags: %d%d%d%d", dns->aa, dns->tc, dns->rd, dns->ra);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Rcode: %d (%s)", dns->rcode, get_dns_rcode(dns->rcode));
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Question: %d, Answer: %d, Authority: %d, Additional records: %d",
              dns->section_count[QDCOUNT], dns->section_count[ANCOUNT],
              dns->section_count[NSCOUNT], dns->section_count[ARCOUNT]);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 0, "");
    for (int i = dns->section_count[QDCOUNT]; i > 0; i--) {
        mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "QNAME: %s, QTYPE: %s, QCLASS: %s",
                  dns->question.qname, get_dns_type_extended(dns->question.qtype),
                  get_dns_class_extended(dns->question.qclass));
    }
    if (records) {
        int mx;
        int len;

        mx = getmaxx(wmain);
        mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Resource records:");
        len = get_max_namelen(dns->record, records);
        for (int i = 0; i < records; i++) {
            char buffer[mx];
            bool soa = false;

            snprintf(buffer, mx, "%-*s", len + 4, dns->record[i].name);
            snprintcat(buffer, mx, "%-6s", get_dns_class(dns->record[i].class));
            snprintcat(buffer, mx, "%-8s", get_dns_type(dns->record[i].type));
            print_dns_record(dns, i, buffer, mx, dns->record[i].type, &soa);
            mvwprintw(line_info[screen_line].win.wsub, ++y, 8, "%s", buffer);
            if (soa) {
                mvwprintw(line_info[screen_line].win.wsub, ++y, 0, "");
                print_dns_soa(dns, i, lineno, y + 1, 8);
            }
        }
    }
}

void print_dns_soa(struct dns_info *info, int i, int lineno, int y, int x)
{
    int screen_line = lineno - top;

    mvwprintw(line_info[screen_line].win.wsub, y, x, "mname: %s", info->record[i].rdata.soa.mname);
    mvwprintw(line_info[screen_line].win.wsub, ++y, x, "rname: %s", info->record[i].rdata.soa.rname);
    mvwprintw(line_info[screen_line].win.wsub, ++y, x, "Serial: %d", info->record[i].rdata.soa.serial);
    mvwprintw(line_info[screen_line].win.wsub, ++y, x, "Refresh: %d", info->record[i].rdata.soa.refresh);
    mvwprintw(line_info[screen_line].win.wsub, ++y, x, "Retry: %d", info->record[i].rdata.soa.retry);
    mvwprintw(line_info[screen_line].win.wsub, ++y, x, "Expire: %d", info->record[i].rdata.soa.expire);
    mvwprintw(line_info[screen_line].win.wsub, ++y, x, "Minimum: %d", info->record[i].rdata.soa.minimum);
}

void print_nbns_verbose(struct nbns_info *nbns, int lineno, int y)
{
    int records = 0;
    int screen_line = lineno - top;

    /* number of resource records */
    for (int i = 1; i < 4; i++) {
        records += nbns->section_count[i];
    }
    mvwprintw(line_info[screen_line].win.wsub, y, 0, "");
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "ID: 0x%x", nbns->id);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Response flag: %d (%s)", nbns->r, nbns->r ? "Response" : "Request");
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Opcode: %d (%s)", nbns->opcode, get_nbns_opcode(nbns->opcode));
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Flags: %d%d%d%d%d", nbns->aa, nbns->tc, nbns->rd, nbns->ra, nbns->broadcast);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Rcode: %d (%s)", nbns->rcode, get_nbns_rcode(nbns->rcode));
    mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Question Entries: %d, Answer RRs: %d, Authority RRs: %d, Additional RRs: %d",
              nbns->section_count[QDCOUNT], nbns->section_count[ANCOUNT],
              nbns->section_count[NSCOUNT], nbns->section_count[ARCOUNT]);
    mvwprintw(line_info[screen_line].win.wsub, ++y, 0, "");

    /* question entry */
    if (nbns->section_count[QDCOUNT]) {
        mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Question name: %s, Question type: %s, Question class: IN (Internet)",
                  nbns->question.qname, get_nbns_type_extended(nbns->question.qtype));
    }

    if (records) {
        int mx;

        mx = getmaxx(wmain);
        mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "Resource records:");
        for (int i = 0; i < records; i++) {
            char buffer[mx];

            snprintf(buffer, mx, "%s\t", nbns->record[i].rrname);
            snprintcat(buffer, mx, "IN\t");
            snprintcat(buffer, mx, "%s\t", get_nbns_type(nbns->record[i].rrtype));
            print_nbns_record(nbns, i, buffer, mx, nbns->record[i].rrtype);
            mvwprintw(line_info[screen_line].win.wsub, ++y, 8, "%s", buffer);
        }
    }
}


void print_ssdp_verbose(list_t *ssdp, int lineno, int y)
{
    const node_t *n;
    int screen_line = lineno - top;

    mvwprintw(line_info[screen_line].win.wsub, y, 0, "");
    n = list_begin(ssdp);
    while (n) {
        mvwprintw(line_info[screen_line].win.wsub, ++y, 4, "%s", (char *) list_data(n));
        n = list_next(n);
    }
    mvwprintw(line_info[screen_line].win.wsub, ++y, 0, "");
    touchwin(wmain);
    wrefresh(line_info[screen_line].win.wsub);
}

void print_http_verbose(struct http_info *http)
{

}
