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

static WINDOW *wheader;
static WINDOW *wmain;
static WINDOW *wstatus;
static WINDOW *wsub_main; /* subwindow of wmain */

static int outy = 0;
static bool interactive = false;
static bool numeric = true;
static int selection_line = 0;
static int top = 0; /* index to top of screen */

/* the number of lines to be scrolled in order to print verbose packet information */
static int scrollvy = 0;

static void print_header();
static void scroll_window();
static void print(char *buf);
static void print_arp(char *buf, int n, struct arp_info *info);
static void print_ip(char *buf, int n, struct ip_info *info);
static void print_udp(char *buf, int n, struct ip_info *info);
static void print_icmp(char *buf, int n, struct ip_info *info);
static void print_igmp(char *buf, int n, struct ip_info *info);
static void print_dns(char *buf, int n, struct ip_info *info);
static void print_nbns(char *buf, int n, struct ip_info *info);
static void print_ssdp(char *buf, int n, struct ip_info *info);

static void print_information(int lineno, bool select);
static void print_arp_verbose(struct arp_info *info);
static void print_ip_verbose(struct ip_info *info);
static void print_udp_verbose(struct ip_info *info);
static void print_dns_verbose(struct dns_info *info);
static void print_dns_soa(struct dns_info *info, int i, int y, int x);
static void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type, bool *soa);
static void print_nbns_verbose(struct nbns_info *info);
static void print_nbns_record(struct nbns_info *info, int i, char *buf, int n, uint16_t type);
static void print_icmp_verbose(struct ip_info *info);
static void print_igmp_verbose(struct ip_info *info);
static void print_ssdp_verbose(struct ssdp_info *info);

static void print_buffer(char *buf, int size, struct packet *p);
static void create_subwindow(int num_lines);
static void delete_subwindow();
static void set_interactive(bool interactive_mode, int lines, int cols);
static void handle_keydown(int lines, int cols);
static void handle_keyup(int lines, int cols);
static void scroll_page(int lines, int cols);
static int print_lines(int from, int to, int y, int cols);

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
}

/* scroll the window if necessary */
void scroll_window()
{
    int mx, my;

    getmaxyx(wmain, my, mx);
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
    static bool selected = false;

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
            selected = !selected;
            print_information(selection_line, selected);
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
    if (selection_line >= vector_size() - 1) return;

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

void create_subwindow(int num_lines)
{
    int mx, my;
    int screen_line;
    int c;

    getmaxyx(wmain, my, mx);
    screen_line = selection_line - top;
    c = selection_line + 1;

    /* if there is not enough space for the information to be printed, the
        screen needs to be scrolled to make room for all the lines */
    if (my - (screen_line + 1) < num_lines) {
        scrollvy = num_lines - (my - (screen_line + 1));
        wscrl(wmain, scrollvy);
        screen_line -= scrollvy;
        selection_line -= scrollvy;
        wrefresh(wmain);
    }

    /* make space for protocol specific information */
    wsub_main = derwin(wmain, num_lines, mx, screen_line + 1, 0);
    wmove(wmain, screen_line + 1, 0);
    wclrtobot(wmain); /* clear everything below selection bar */
    outy = screen_line + num_lines + 1;

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
    delwin(wsub_main);
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

/*
 * Print more information about a packet. This will print more details about the
 * specific protocol header and payload.
 */
void print_information(int lineno, bool select)
{
    if (select) {
        struct packet *p;

        p = vector_get_data(lineno);
        switch (p->ut) {
        case ARP:
            print_arp_verbose(&p->arp);
            break;
        case IPv4:
            print_ip_verbose(&p->ip);
            break;
        default:
            break;
        }
    } else {
        delete_subwindow();
    }
}

void print_arp_verbose(struct arp_info *info)
{
    int y = 0;

    create_subwindow(10);
    mvwprintw(wsub_main, y, 0, "");
    mvwprintw(wsub_main, ++y, 4, "Hardware type: %d (%s)", info->ht, get_arp_hardware_type(info->ht));
    mvwprintw(wsub_main, ++y, 4, "Protocol type: 0x%x (%s)", info->pt, get_arp_protocol_type(info->pt));
    mvwprintw(wsub_main, ++y, 4, "Hardware size: %d", info->hs);
    mvwprintw(wsub_main, ++y, 4, "Protocol size: %d", info->ps);
    mvwprintw(wsub_main, ++y, 4, "Opcode: %d (%s)", info->op, get_arp_opcode(info->op));
    mvwprintw(wsub_main, ++y, 0, "");
    mvwprintw(wsub_main, ++y, 4, "Sender IP: %-15s  HW: %s", info->sip, info->sha);
    mvwprintw(wsub_main, ++y, 4, "Target IP: %-15s  HW: %s", info->tip, info->tha);
    touchwin(wmain);
    wrefresh(wsub_main);
}

void print_ip_verbose(struct ip_info *info)
{
    switch (info->protocol) {
    case IPPROTO_ICMP:
        print_icmp_verbose(info);
        break;
    case IPPROTO_IGMP:
        print_igmp_verbose(info);
        break;
    case IPPROTO_TCP:
        break;
    case IPPROTO_UDP:
        print_udp_verbose(info);
    default:
        break;
    }
}

void print_icmp_verbose(struct ip_info *info)
{
    int y = 0;

    if (info->icmp.type == ICMP_ECHOREPLY || info->icmp.type == ICMP_ECHO) {
        create_subwindow(7);
    } else {
        create_subwindow(5);
    }
    mvwprintw(wsub_main, y, 0, "");
    mvwprintw(wsub_main, ++y, 4, "Type: %d (%s)", info->icmp.type, get_icmp_type(info->icmp.type));
    switch (info->icmp.type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        mvwprintw(wsub_main, ++y, 4, "Code: %d", info->icmp.code);
        break;
    case ICMP_DEST_UNREACH:
        mvwprintw(wsub_main, ++y, 4, "Code: %d (%s)", info->icmp.code, get_icmp_dest_unreach_code(info->icmp.code));
        break;
    default:
        break;
    }
    mvwprintw(wsub_main, ++y, 4, "Checksum: %d", info->icmp.checksum);
    if (info->icmp.type == ICMP_ECHOREPLY || info->icmp.type == ICMP_ECHO) {
        mvwprintw(wsub_main, ++y, 4, "Identifier: 0x%x", info->icmp.echo.id);
        mvwprintw(wsub_main, ++y, 4, "Sequence number: %d", info->icmp.echo.seq_num);
    }
    mvwprintw(wsub_main, ++y, 0, "");
    touchwin(wmain);
    wrefresh(wsub_main);
}

void print_igmp_verbose(struct ip_info *info)
{
    int y = 0;

    create_subwindow(6);
    mvwprintw(wsub_main, y, 0, "");
    mvwprintw(wsub_main, ++y, 4, "Type: %d (%s) ", info->igmp.type, get_igmp_type(info->icmp.type));
    if (info->igmp.type == IGMP_HOST_MEMBERSHIP_QUERY) {
        if (!strcmp(info->igmp.group_addr, "0.0.0.0")) {
            mvwprintw(wsub_main, y, 4, "General query", info->igmp.type, get_igmp_type(info->icmp.type));
        } else {
            mvwprintw(wsub_main, y, 4, "Group-specific query", info->igmp.type, get_igmp_type(info->icmp.type));
        }
    }
    mvwprintw(wsub_main, ++y, 4, "Max response time: %d seconds", info->igmp.max_resp_time / 10);
    mvwprintw(wsub_main, ++y, 4, "Checksum: %d", info->igmp.checksum);
    mvwprintw(wsub_main, ++y, 4, "Group address: %s", info->igmp.group_addr);
    mvwprintw(wsub_main, ++y, 0, "");
    touchwin(wmain);
    wrefresh(wsub_main);
}

void print_udp_verbose(struct ip_info *info)
{
    switch (info->udp.utype) {
    case DNS:
        print_dns_verbose(info->udp.dns);
        break;
    case NBNS:
        print_nbns_verbose(info->udp.nbns);
        break;
    case SSDP:
        print_ssdp_verbose(info->udp.ssdp);
        break;
    default:
        break;
    }
}

void print_dns_verbose(struct dns_info *info)
{
    int y = 0;
    int i = 1;
    int records = 0;
    int authority = info->section_count[NSCOUNT];

    /* number of resource records */
    while (i < 4) {
        records += info->section_count[i++];
    }
    create_subwindow(authority ? 19 + records : 11 + records);
    mvwprintw(wsub_main, y, 0, "");
    mvwprintw(wsub_main, ++y, 4, "ID: 0x%x", info->id);
    mvwprintw(wsub_main, ++y, 4, "QR: %d (%s)", info->qr, info->qr ? "DNS Response" : "DNS Query");
    mvwprintw(wsub_main, ++y, 4, "Opcode: %d (%s)", info->opcode, get_dns_opcode(info->opcode));
    mvwprintw(wsub_main, ++y, 4, "Flags: %d%d%d%d", info->aa, info->tc, info->rd, info->ra);
    mvwprintw(wsub_main, ++y, 4, "Rcode: %d (%s)", info->rcode, get_dns_rcode(info->rcode));
    mvwprintw(wsub_main, ++y, 4, "Question: %d, Answer: %d, Authority: %d, Additional records: %d",
              info->section_count[QDCOUNT], info->section_count[ANCOUNT],
              info->section_count[NSCOUNT], info->section_count[ARCOUNT]);
    mvwprintw(wsub_main, ++y, 0, "");
    i = info->section_count[QDCOUNT];
    while (i--) {
        mvwprintw(wsub_main, ++y, 4, "QNAME: %s, QTYPE: %s, QCLASS: %s",
                  info->question.qname, get_dns_type_extended(info->question.qtype),
                  get_dns_class_extended(info->question.qclass));
    }
    if (records) {
        int mx, my;
        int len;

        getmaxyx(wmain, my, mx);
        mvwprintw(wsub_main, ++y, 4, "Resource records:");
        len = get_max_namelen(info->record, records);
        for (int i = 0; i < records; i++) {
            char buffer[mx];
            bool soa = false;

            snprintf(buffer, mx, "%-*s", len + 4, info->record[i].name);
            snprintcat(buffer, mx, "%-6s", get_dns_class(info->record[i].class));
            snprintcat(buffer, mx, "%-8s", get_dns_type(info->record[i].type));
            print_dns_record(info, i, buffer, mx, info->record[i].type, &soa);
            mvwprintw(wsub_main, ++y, 8, "%s", buffer);
            if (soa) {
                mvwprintw(wsub_main, ++y, 0, "");
                print_dns_soa(info, i, y + 1, 8);
            }
        }
    }
    touchwin(wmain);
    wrefresh(wsub_main);
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

void print_dns_soa(struct dns_info *info, int i, int y, int x)
{
    mvwprintw(wsub_main, y, x, "mname: %s", info->record[i].rdata.soa.mname);
    mvwprintw(wsub_main, ++y, x, "rname: %s", info->record[i].rdata.soa.rname);
    mvwprintw(wsub_main, ++y, x, "Serial: %d", info->record[i].rdata.soa.serial);
    mvwprintw(wsub_main, ++y, x, "Refresh: %d", info->record[i].rdata.soa.refresh);
    mvwprintw(wsub_main, ++y, x, "Retry: %d", info->record[i].rdata.soa.retry);
    mvwprintw(wsub_main, ++y, x, "Expire: %d", info->record[i].rdata.soa.expire);
    mvwprintw(wsub_main, ++y, x, "Minimum: %d", info->record[i].rdata.soa.minimum);
}

void print_nbns_verbose(struct nbns_info *info)
{
    int y = 0;
    int i = 1;
    int records = 0;

    /* number of resource records */
    while (i < 4) {
        records += info->section_count[i++];
    }
    create_subwindow(10 + records);
    mvwprintw(wsub_main, y, 0, "");
    mvwprintw(wsub_main, ++y, 4, "ID: 0x%x", info->id);
    mvwprintw(wsub_main, ++y, 4, "Response flag: %d (%s)", info->r, info->r ? "Response" : "Request");
    mvwprintw(wsub_main, ++y, 4, "Opcode: %d (%s)", info->opcode, get_nbns_opcode(info->opcode));
    mvwprintw(wsub_main, ++y, 4, "Flags: %d%d%d%d%d", info->aa, info->tc, info->rd, info->ra, info->broadcast);
    mvwprintw(wsub_main, ++y, 4, "Rcode: %d (%s)", info->rcode, get_nbns_rcode(info->rcode));
    mvwprintw(wsub_main, ++y, 4, "Question Entries: %d, Answer RRs: %d, Authority RRs: %d, Additional RRs: %d",
              info->section_count[QDCOUNT], info->section_count[ANCOUNT],
              info->section_count[NSCOUNT], info->section_count[ARCOUNT]);
    mvwprintw(wsub_main, ++y, 0, "");

    /* question entry */
    if (info->section_count[QDCOUNT]) {
        mvwprintw(wsub_main, ++y, 4, "Question name: %s, Question type: %s, Question class: IN (Internet)",
                  info->question.qname, get_nbns_type_extended(info->question.qtype));
    }

    if (records) {
        int mx, my;

        getmaxyx(wmain, my, mx);
        mvwprintw(wsub_main, ++y, 4, "Resource records:");
        for (int i = 0; i < records; i++) {
            char buffer[mx];

            snprintf(buffer, mx, "%s\t", info->record[i].rrname);
            snprintcat(buffer, mx, "IN\t");
            snprintcat(buffer, mx, "%s\t", get_nbns_type(info->record[i].rrtype));
            print_nbns_record(info, i, buffer, mx, info->record[i].rrtype);
            mvwprintw(wsub_main, ++y, 8, "%s", buffer);
        }
    }
    touchwin(wmain);
    wrefresh(wsub_main);
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

void print_ssdp_verbose(struct ssdp_info *ssdp)
{
    list_t *ssdp_fields;
    const node_t *n;
    int y = 0;

    ssdp_fields = list_init(NULL);
    parse_ssdp(ssdp->str, ssdp->n, &ssdp_fields);
    create_subwindow(list_size(ssdp_fields) + 2);
    mvwprintw(wsub_main, y, 0, "");
    n = list_begin(ssdp_fields);
    while (n) {
        mvwprintw(wsub_main, ++y, 4, "%s", (char *) list_data(n));
        n = list_next(n);
    }
    list_free(ssdp_fields);
    mvwprintw(wsub_main, ++y, 0, "");
    touchwin(wmain);
    wrefresh(wsub_main);
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
    int my, mx;

    getmaxyx(wmain, my, mx);

    char buf[mx];
    print_buffer(buf, mx, p);
    print(buf);
}

/* write packet to buffer */
void print_buffer(char *buf, int size, struct packet *p)
{
    switch (p->ut) {
    case ARP:
        print_arp(buf, size, &p->arp);
        break;
    case IPv4:
        print_ip(buf, size, &p->ip);
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
    int mx, my;

    getmaxyx(wmain, my, mx);
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
                     info->protocol == IPPROTO_UDP && info->udp.dns->qr == -1)) {
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
        PRINT_PROTOCOL(buf, n, "TCP");
        break;
    case IPPROTO_UDP:
        print_udp(buf, n, info);
        break;
    default:
        break;
    }
}

void print_udp(char *buf, int n, struct ip_info *info)
{
    switch (info->udp.utype) {
    case DNS:
        print_dns(buf, n, info);
        break;
    case NBNS:
        print_nbns(buf, n, info);
        break;
    case SSDP:
        print_ssdp(buf, n, info);
        break;
    default:
        PRINT_PROTOCOL(buf, n, "UDP");
        PRINT_INFO(buf, n, "Source port: %d  Destination port: %d", info->udp.src_port,
                   info->udp.dst_port);
        break;
    }
}

void print_dns(char *buf, int n, struct ip_info *info)
{
    PRINT_PROTOCOL(buf, n, "DNS");
    if (info->udp.dns->qr == 0) {
        switch (info->udp.dns->opcode) {
        case DNS_QUERY:
            PRINT_INFO(buf, n, "Standard query: ");
            PRINT_INFO(buf, n, "%s ", info->udp.dns->question.qname);
            PRINT_INFO(buf, n, "%s ", get_dns_class(info->udp.dns->question.qclass));
            PRINT_INFO(buf, n, "%s", get_dns_type(info->udp.dns->question.qtype));
            break;
        case DNS_IQUERY:
            PRINT_INFO(buf, n, "Inverse query");
            break;
        case DNS_STATUS:
            PRINT_INFO(buf, n, "Server status request");
            break;
        }
    } else {
        switch (info->udp.dns->rcode) {
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
        PRINT_INFO(buf, n, "%s ", info->udp.dns->record[0].name);
        PRINT_INFO(buf, n, "%s ", get_dns_class(info->udp.dns->record[0].class));
        PRINT_INFO(buf, n, "%s ", get_dns_type(info->udp.dns->record[0].type));
        for (int i = 0; i < info->udp.dns->section_count[ANCOUNT]; i++) {
            print_dns_record(info->udp.dns, i, buf, n, info->udp.dns->record[i].type, NULL);
            PRINT_INFO(buf, n, " ");
        }
    }
}

void print_nbns(char *buf, int n, struct ip_info *info)
{
    PRINT_PROTOCOL(buf, n, "NBNS");
    if (info->udp.nbns->r == 0) {
        char opcode[16];

        strncpy(opcode, get_nbns_opcode(info->udp.nbns->opcode), sizeof(opcode));
        PRINT_INFO(buf, n, "Name %s request: ", strtolower(opcode, strlen(opcode)));
        PRINT_INFO(buf, n, "%s ", info->udp.nbns->question.qname);
        PRINT_INFO(buf, n, "%s ", get_nbns_type(info->udp.nbns->question.qtype));
        if (info->udp.nbns->section_count[ARCOUNT]) {
            print_nbns_record(info->udp.nbns, 0, buf, n, info->udp.nbns->record[0].rrtype);
        }
    } else {
        switch (info->udp.nbns->rcode) {
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

        strncpy(opcode, get_nbns_opcode(info->udp.nbns->opcode), sizeof(opcode));
        PRINT_INFO(buf, n, "Name %s response: ", strtolower(opcode, strlen(opcode)));
        PRINT_INFO(buf, n, "%s ", info->udp.nbns->record[0].rrname);
        PRINT_INFO(buf, n, "%s ", get_nbns_type(info->udp.nbns->record[0].rrtype));
        print_nbns_record(info->udp.nbns, 0, buf, n, info->udp.nbns->record[0].rrtype);
    }
}

void print_ssdp(char *buf, int n, struct ip_info *info)
{
    char *p;

    PRINT_PROTOCOL(buf, n, "SSDP");
    p = strchr(info->udp.ssdp->str, '\r');
    if (*(p + 1) == '\n') {
        int len;
        int buflen;

        len = p - info->udp.ssdp->str;
        buflen = strlen(buf);
        if (buflen + len + 1 < n) {
            strncpy(buf + buflen, info->udp.ssdp->str, len);
            buf[buflen + len] = '\0';
        }
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
