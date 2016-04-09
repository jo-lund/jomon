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
static int interactive = 0;
static int numeric = 1;
static int screen_line = 0;

/* the number of lines to be scrolled in order to print verbose packet information */
static int scrollvy = 0;

static void print_header();
static void scroll_window();
static void print(char *buf, int key);
static void print_arp(char *buffer, struct arp_info *info);
static void print_ip(char *buffer, struct ip_info *info);
static void print_udp(struct ip_info *info, char *buf);
static void print_icmp(struct ip_info *info, char *buf);
static void print_igmp(struct ip_info *info, char *buf);
static void print_dns(struct ip_info *info, char *buf);
static void print_dns_class(char *buf, uint16_t class, int n);
static void print_dns_type(struct ip_info *info, char *buf, uint16_t type, int n);
static void print_nbns(struct ip_info *info, char *buf);
static void print_nbns_opcode(char *buf, uint8_t opcode, int n);
static void print_nbns_type(char *buf, uint8_t type, int n);
static void print_nbns_record(struct ip_info *info, char *buf, int n);

static void print_information(int lineno, bool select);
static void print_arp_verbose(struct arp_info *info);
static void print_ip_verbose(struct ip_info *info);
static void print_udp_verbose(struct ip_info *info);
static void print_dns_verbose(struct dns_info *info);
static void print_dns_soa(struct dns_info *info, int i, int y, int x);

static char *alloc_print_buffer(struct packet *p, int size);
static void create_subwindow(int num_lines);
static void delete_subwindow();

void init_ncurses()
{
    initscr(); /* initialize curses mode */
    cbreak(); /* disable line buffering */
    noecho();
    curs_set(0); /* make the cursor invisible */
    use_default_colors();
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_CYAN);
}

void end_ncurses()
{
    endwin(); /* end curses mode */
    list_clear();
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
        list_pop_front(); /* list will always contain the lines on the visible screen */
    }
}

void get_input()
{
    int c = 0;
    static int selection_line = 0;
    static bool selected = false;

    c = wgetch(wmain);
    switch (c) {
    case 'i':
        if (interactive) {
            int mx, my;

            getmaxyx(wmain, my, mx);
            if (outy >= my) {
                struct packet p;
                unsigned char *buf;
                int c = vector_size() - 1;

                werase(wmain);
                list_clear();

                /* print the new lines stored in vector from bottom to top of screen */
                for (int i = my - 1; i >= 0; i--, c--) {
                    char *buffer;

                    buf = vector_get_data(c);
                    handle_ethernet(buf, &p); /* deserialize packet */
                    buffer = alloc_print_buffer(&p, mx + 1);
                    mvwprintw(wmain, i, 0, "%s", buffer);
                    list_push_front(buffer);
                }
            }
            interactive = 0;
            werase(wstatus);
            wrefresh(wstatus);

            /* remove selection bar */
            mvwchgat(wmain, screen_line, 0, -1, A_NORMAL, 0, NULL);
            wrefresh(wmain);
            screen_line = 0;
        } else {
            int my, mx;
            int lineno;

            interactive = 1;
            mvwprintw(wstatus, 0, 0, "(interactive)");
            wrefresh(wstatus);
            getmaxyx(wmain, my, mx);
            lineno = vector_size() - 1; /* bottom line number */
            selection_line = lineno - (my - 1); /* top line on screen */
            if (selection_line < 0) selection_line = 0;

            /* print selection bar */
            mvwchgat(wmain, 0, 0, -1, A_NORMAL, 1, NULL);
            wrefresh(wmain);
        }
        break;
    case 'q':
        kill(0, SIGINT);
        break;
    case 'n':
        numeric = !numeric;
        break;
    case KEY_UP:
    {
        int mx, my;

        getmaxyx(wmain, my, mx);
        if (selection_line > 0 && screen_line == 0) {
            unsigned char *buf;
            struct packet p;
            char *buffer;

            selection_line--;
            list_pop_back();
            wscrl(wmain, -1);
            buf = vector_get_data(selection_line);
            handle_ethernet(buf, &p); /* deserialize packet */
            buffer = alloc_print_buffer(&p, mx + 1);
            print(buffer, KEY_UP);

            /* deselect previous line and highlight next at top */
            mvwchgat(wmain, 1, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain, 0, 0, -1, A_NORMAL, 1, NULL);
        } else if (selection_line > 0) {
            /* deselect previous line and highlight next */
            mvwchgat(wmain, screen_line, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain, --screen_line, 0, -1, A_NORMAL, 1, NULL);
            selection_line--;
        }
        wrefresh(wmain);
        break;
    }
    case KEY_DOWN:
    {
        int mx, my;

        getmaxyx(wmain, my, mx);

        /* scroll screen if the selection bar is at the bottom */
        if (screen_line == my - 1) {
            if (selection_line + 1 > vector_size()) return;
            unsigned char *buf = vector_get_data(++selection_line);
            struct packet p;

            if (buf) {
                char *buffer;

                list_pop_front();
                wscrl(wmain, 1);
                handle_ethernet(buf, &p); /* deserialize packet */
                buffer = alloc_print_buffer(&p, mx + 1);
                print(buffer, KEY_DOWN);

                /* deselect previous line and highlight next line at bottom */
                mvwchgat(wmain, my - 2, 0, -1, A_NORMAL, 0, NULL);
                mvwchgat(wmain, my - 1, 0, -1, A_NORMAL, 1, NULL);
            }
        } else {
            /* deselect previous line and highlight next */
            mvwchgat(wmain, screen_line, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain, ++screen_line, 0, -1, A_NORMAL, 1, NULL);
            selection_line++;
        }
        wrefresh(wmain);
        break;
    }
    case KEY_ENTER:
    case '\n':
        if (interactive) {
            selected = !selected;
            print_information(selection_line, selected);
        }
        break;
    default:
        break;
    }
}

void create_subwindow(int num_lines)
{
    int mx, my;
    const node_t *l = list_ith(screen_line + 1);

    getmaxyx(wmain, my, mx);

    /* if there is not enough space for the information to be printed, the
        screen needs to be scrolled to make room for all the lines */
    if (my - (screen_line + 1) < num_lines) {
        scrollvy = num_lines - (my - (screen_line + 1));
        wscrl(wmain, scrollvy);
        screen_line -= scrollvy;
        wrefresh(wmain);
    }

    /* make space for protocol specific information */
    wsub_main = derwin(wmain, num_lines, mx, screen_line + 1, 0);
    wmove(wmain, screen_line + 1, 0);
    wclrtobot(wmain); /* clear everything below selection bar */
    outy = screen_line + num_lines + 1;

    /* print the remaining lines on the screen below the sub window */
    if (!scrollvy) {
        while (l) {
            mvwprintw(wmain, outy++, 0, "%s", (char *) list_data(l));
            l = list_next(l);
        }
    }
    wrefresh(wmain);
}

void delete_subwindow()
{
    /*
     * Print the entire screen. This can be optimized to just print the lines
     * that are below the selected line
     */
    const node_t *l = list_begin();

    if (scrollvy) {
        screen_line += scrollvy;
        scrollvy = 0;
    }
    delwin(wsub_main);
    werase(wmain);
    outy = 0;
    while (l) {
        mvwprintw(wmain, outy++, 0, "%s", (char *) list_data(l));
        l = list_next(l);
    }
    mvwchgat(wmain, screen_line, 0, -1, A_NORMAL, 1, NULL);
    wrefresh(wmain);
}

/*
 * Print more information about a packet. This will print more details about the
 * specific protocol header and payload.
 */
void print_information(int lineno, bool select)
{
    if (select) {
        unsigned char *buf;
        struct packet p;

        buf = vector_get_data(lineno);
        handle_ethernet(buf, &p);
        switch (p.ut) {
        case ARP:
            print_arp_verbose(&p.arp);
            break;
        case IPv4:
            print_ip_verbose(&p.ip);
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
        break;
    case IPPROTO_IGMP:
        break;
    case IPPROTO_TCP:
        break;
    case IPPROTO_UDP:
        print_udp_verbose(info);
    default:
        break;
    }
}

void print_udp_verbose(struct ip_info *info)
{
    switch (info->udp.utype) {
    case DNS:
        print_dns_verbose(&info->udp.dns);
        break;
    case NBNS:
        //print_nbns_verbose(info->udp.nbns);
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

        i = 0;
        getmaxyx(wmain, my, mx);
        mvwprintw(wsub_main, ++y, 4, "Resource records:");
        while (records--) {
            char buffer[mx + 1];

            snprintf(buffer, mx + 1, "%s\t", info->record[i].name);
            snprintcat(buffer, mx + 1, "%-6s", get_dns_class(info->record[i].class));
            snprintcat(buffer, mx + 1, "%-8s", get_dns_type(info->record[i].type));
            switch (info->record[i].type) {
            case DNS_TYPE_A:
            {
                char addr[INET_ADDRSTRLEN];
                uint32_t haddr = htonl(info->record[i].rdata.address);

                inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr));
                snprintcat(buffer, mx + 1, "%s", addr);
                mvwprintw(wsub_main, ++y, 8, "%s", buffer);
                break;
            }
            case DNS_TYPE_NS:
                snprintcat(buffer, mx + 1, "%s", info->record[i].rdata.nsdname);
                mvwprintw(wsub_main, ++y, 8, "%s", buffer);
                break;
            case DNS_TYPE_CNAME:
                snprintcat(buffer, mx + 1, "%s", info->record[i].rdata.cname);
                mvwprintw(wsub_main, ++y, 8, "%s", buffer);
                break;
            case DNS_TYPE_SOA:
                mvwprintw(wsub_main, ++y, 8, "%s", buffer);
                mvwprintw(wsub_main, ++y, 0, "");
                print_dns_soa(info, i, y + 1, 8);
                break;
            case DNS_TYPE_PTR:
                snprintcat(buffer, mx + 1, "%s", info->record[i].rdata.ptrdname);
                mvwprintw(wsub_main, ++y, 8, "%s", buffer);
                break;
            case DNS_TYPE_AAAA:
            {
                char addr[INET6_ADDRSTRLEN];
                
                inet_ntop(AF_INET6, (struct in_addr *) info->record[i].rdata.ipv6addr, addr, sizeof(addr));
                snprintcat(buffer, mx + 1, "%s", addr);
                mvwprintw(wsub_main, ++y, 8, "%s", buffer);
                break;
            }
            default:
                snprintcat(buffer, mx + 1, "type: %d", info->record[i].type);
                mvwprintw(wsub_main, ++y, 8, "%s", buffer);
                break;
            }
            i++;
        }
    }
    touchwin(wmain);
    wrefresh(wsub_main);
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
    char *buffer;
    int my, mx;

    getmaxyx(wmain, my, mx);
    buffer = alloc_print_buffer(p, mx + 1);
    print(buffer, -1);
}

/* allocate buffer with specified size and write packet to buffer */
char *alloc_print_buffer(struct packet *p, int size)
{
    char *buffer;

    buffer = (char *) malloc(size);
    switch (p->ut) {
    case ARP:
        print_arp(buffer, &p->arp);
        break;
    case IPv4:
        print_ip(buffer, &p->ip);
        break;
    default:
        break;
    }
    return buffer;
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

/* print buffer to standard output */
void print(char *buf, int key)
{
    int mx, my;

    getmaxyx(wmain, my, mx);
    switch (key) {
    case KEY_UP:
        list_push_front(buf);
        mvwprintw(wmain, 0, 0, "%s", buf);
        wrefresh(wmain);
        break;
    case KEY_DOWN:
        list_push_back(buf);
        mvwprintw(wmain, my - 1, 0, "%s", buf);
        wrefresh(wmain);
        break;
    default: /* new packet from the network interface */
        if (!interactive || (interactive && outy < my)) {
            list_push_back(buf); /* buffer every line on screen */
            scroll_window();
            mvwprintw(wmain, outy, 0, "%s", buf);
            outy++;
            wrefresh(wmain);
        }
        break;
    }
}

/* print ARP frame information */
void print_arp(char *buffer, struct arp_info *info)
{
    int mx, my;

    getmaxyx(wmain, my, mx);
    switch (info->op) {
    case ARPOP_REQUEST:
        PRINT_LINE(buffer, mx + 1, info->sip, info->tip, "ARP",
                   "Request: Looking for hardware address of %s", info->tip);
        break;
    case ARPOP_REPLY:
        PRINT_LINE(buffer, mx + 1, info->sip, info->tip, "ARP",
                   "Reply: %s has hardware address %s", info->sip, info->sha);
        break;
    default:
        PRINT_LINE(buffer, mx + 1, info->sip, info->tip, "ARP", "Opcode %d", info->op);
        break;
    }
}

/* print IP packet information */
void print_ip(char *buffer, struct ip_info *info)
{
    int mx, my;

    getmaxyx(wmain, my, mx);
    if (!numeric && (info->protocol != IPPROTO_UDP ||
                     info->protocol == IPPROTO_UDP && info->udp.dns.qr == -1)) {
        char sname[HOSTNAMELEN];
        char dname[HOSTNAMELEN];

        /* get the host name of source and destination */
        gethost(info->src, sname, HOSTNAMELEN);
        gethost(info->dst, dname, HOSTNAMELEN);
        // TEMP: Fix this!
        sname[35] = '\0';
        dname[35] = '\0';
        PRINT_ADDRESS(buffer, mx + 1, sname, dname);
    } else {
        PRINT_ADDRESS(buffer, mx + 1, info->src, info->dst);
    }
    switch (info->protocol) {
    case IPPROTO_ICMP:
        print_icmp(info, buffer);
        break;
    case IPPROTO_IGMP:
        print_igmp(info, buffer);
        break;
    case IPPROTO_TCP:
        PRINT_PROTOCOL(buffer, mx + 1, "TCP");
        break;
    case IPPROTO_UDP:
        print_udp(info, buffer);
        break;
    default:
        break;
    }
}

void print_udp(struct ip_info *info, char *buf)
{
    switch (info->udp.utype) {
    case DNS:
        print_dns(info, buf);
        break;
    case NBNS:
        print_nbns(info, buf);
        break;
    default:
    {
        int mx, my;

        getmaxyx(wmain, my, mx);
        PRINT_PROTOCOL(buf, mx + 1, "UDP");
        PRINT_INFO(buf, mx + 1, "Source port: %d  Destination port: %d", info->udp.src_port,
                   info->udp.dst_port);
        break;
    }
    }
}

void print_dns(struct ip_info *info, char *buf)
{
    int mx, my;

    getmaxyx(wmain, my, mx);
    PRINT_PROTOCOL(buf, mx + 1, "DNS");
    if (info->udp.dns.qr == 0) {
        switch (info->udp.dns.opcode) {
        case DNS_QUERY:
            PRINT_INFO(buf, mx + 1, "Standard query: ");
            print_dns_type(info, buf, info->udp.dns.question.qtype, mx + 1);
            PRINT_INFO(buf, mx + 1, " %s", info->udp.dns.question.qname);
            print_dns_class(buf, info->udp.dns.question.qclass, mx + 1);
            break;
        case DNS_IQUERY:
            PRINT_INFO(buf, mx + 1, "Inverse query");
            break;
        case DNS_STATUS:
            PRINT_INFO(buf, mx + 1, "Server status request");
            break;
        }
    } else {
        switch (info->udp.dns.rcode) {
        case DNS_FORMAT_ERROR:
            PRINT_INFO(buf, mx + 1, "Response: format error");
            return;
        case DNS_SERVER_FAILURE:
            PRINT_INFO(buf, mx + 1, "Response: server failure");
            return;
        case DNS_NAME_ERROR:
            PRINT_INFO(buf, mx + 1, "Response: name error");
            return;
        case DNS_NOT_IMPLEMENTED:
            PRINT_INFO(buf, mx + 1, "Response: request not supported");
            return;
        case DNS_REFUSED:
            PRINT_INFO(buf, mx + 1, "Response: operation refused");
            return;
        case DNS_NO_ERROR:
        default:
            PRINT_INFO(buf, mx + 1, "Response: ");
            break;
        }
        print_dns_type(info, buf, info->udp.dns.record[0].type, mx + 1);
        print_dns_class(buf, info->udp.dns.record[0].class, mx + 1);
    }
}

void print_dns_type(struct ip_info *info, char *buf, uint16_t type, int n)
{
    switch (type) {
    case DNS_TYPE_A:
        PRINT_INFO(buf, n, "A");
        if (info->udp.dns.qr) {
            char addr[INET_ADDRSTRLEN];
            uint32_t haddr = htonl(info->udp.dns.record[0].rdata.address);

            if (inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr)) == NULL) {
                err_msg("inet_ntop error");
            }
            PRINT_INFO(buf, n, " %s", addr);
        }
        break;
    case DNS_TYPE_NS:
        PRINT_INFO(buf, n, "NSDNAME");
        if (info->udp.dns.qr) {
            PRINT_INFO(buf, n, " %s", info->udp.dns.record[0].rdata.nsdname);
        }
        break;
    case DNS_TYPE_CNAME:
        PRINT_INFO(buf, n, "CNAME");
        if (info->udp.dns.qr) {
            PRINT_INFO(buf, n, " %s", info->udp.dns.record[0].rdata.cname);
        }
        break;
    case DNS_TYPE_PTR:
        PRINT_INFO(buf, n, "PTR");
        if (info->udp.dns.qr) {
            PRINT_INFO(buf, n, " %s", info->udp.dns.record[0].rdata.ptrdname);
        }
        break;
    case DNS_TYPE_AAAA:
        PRINT_INFO(buf, n, "AAAA");
        if (info->udp.dns.qr) {
            char addr[INET6_ADDRSTRLEN];

            inet_ntop(AF_INET6, (struct in_addr *) info->udp.dns.record[0].rdata.ipv6addr, addr, sizeof(addr));
            PRINT_INFO(buf, n, " %s", addr);
        }
        break;
    default:
        PRINT_INFO(buf, n, "TYPE = %d", type);
        break;
    }
}

void print_dns_class(char *buf, uint16_t class, int n)
{
    switch (class) {
    case DNS_CLASS_IN:
        PRINT_INFO(buf, n, " IN");
        break;
    case DNS_CLASS_CS:
        PRINT_INFO(buf, n, " CS");
        break;
    case DNS_CLASS_CH:
        PRINT_INFO(buf, n, " CH");
        break;
    case DNS_CLASS_HS:
        PRINT_INFO(buf, n, " HS");
        break;
    default:
        break;
    }
}

void print_nbns(struct ip_info *info, char *buf)
{
    int mx, my;

    getmaxyx(wmain, my, mx);
    PRINT_PROTOCOL(buf, mx + 1, "NBNS");
    if (info->udp.nbns.r == 0) {
        print_nbns_opcode(buf, info->udp.nbns.opcode, mx + 1);
        PRINT_INFO(buf, mx + 1, " request:");
        print_nbns_type(buf, info->udp.nbns.question.qtype, mx + 1);
        PRINT_INFO(buf, mx + 1, " %s", info->udp.nbns.question.qname);
        if (info->udp.nbns.rr) {
            print_nbns_record(info, buf, mx + 1);
        }
    } else {
        switch (info->udp.nbns.rcode) {
        case NBNS_FMT_ERR:
            PRINT_INFO(buf, mx + 1, "Format Error. Request was invalidly formatted");
            return;
        case NBNS_SRV_ERR:
            PRINT_INFO(buf, mx + 1, "Server failure. Problem with NBNS, cannot process name");
            return;
        case NBNS_IMP_ERR:
            PRINT_INFO(buf, mx + 1, "Unsupported request error");
            return;
        case NBNS_RFS_ERR:
            PRINT_INFO(buf, mx + 1, "Refused error");
            return;
        case NBNS_ACT_ERR:
            PRINT_INFO(buf, mx + 1, "Active error. Name is owned by another node");
            return;
        case NBNS_CFT_ERR:
            PRINT_INFO(buf, mx + 1, "Name in conflict error");
            return;
        default:
            break;
        }
        print_nbns_opcode(buf, info->udp.nbns.opcode, mx + 1);
        PRINT_INFO(buf, mx + 1, " response:");
        print_nbns_type(buf, info->udp.nbns.record[0].rrtype, mx + 1);
        PRINT_INFO(buf, mx + 1, " %s", info->udp.nbns.record[0].rrname);
        print_nbns_record(info, buf, mx + 1);
    }
}

void print_nbns_opcode(char *buf, uint8_t opcode, int n)
{
    switch (opcode) {
    case NBNS_QUERY:
        PRINT_INFO(buf, n, "Name query");
        break;
    case NBNS_REGISTRATION:
        PRINT_INFO(buf, n, "Name registration");
        break;
    case NBNS_REFRESH:
        PRINT_INFO(buf, n, "Name refresh");
        break;
    default:
        PRINT_INFO(buf, n, "Opcode: %d", opcode);
        break;
    }
}

void print_nbns_type(char *buf, uint8_t type, int n)
{
    switch (type) {
    case NBNS_NB:
        PRINT_INFO(buf, n, " NB");
        break;
    case NBNS_NBSTAT:
        PRINT_INFO(buf, n, " Node status request");
        break;
    default:
        PRINT_INFO(buf, n, " TYPE = %d", type);
        break;
    }
}

void print_nbns_record(struct ip_info *info, char *buf, int n)
{
    switch (info->udp.nbns.record[0].rrtype) {
    case NBNS_NB:
    {
        if (info->udp.nbns.record[0].rdata.nb.g) {
            PRINT_INFO(buf, n, "  Group NetBIOS name");
        } else {
            PRINT_INFO(buf, n, "  Unique NetBIOS name");
        }
        char addr[INET_ADDRSTRLEN];
        uint32_t haddr = htonl(info->udp.nbns.record[0].rdata.nb.address[0]);

        if (inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr)) == NULL) {
            err_msg("inet_ntop error");
        }
        PRINT_INFO(buf, n, " %s", addr);
        break;
    }
    case NBNS_NS:
        PRINT_INFO(buf, n, " NSD Name: %s", info->udp.nbns.record[0].rdata.nsdname);
        break;
    case NBNS_A:
    {
        char addr[INET_ADDRSTRLEN];
        uint32_t haddr = htonl(info->udp.nbns.record[0].rdata.nsdipaddr);

        if (inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr)) == NULL) {
            err_msg("inet_ntop error");
        }
        PRINT_INFO(buf, n, " NSD IP address: %s", addr);
        break;
    }
    case NBNS_NBSTAT:
        PRINT_INFO(buf, n, "NBSTAT");
        break;
    default:
        break;
    }
}

void print_icmp(struct ip_info *info, char *buf)
{
    int mx, my;

    getmaxyx(wmain, my, mx);
    PRINT_PROTOCOL(buf, mx + 1, "ICMP");
    switch (info->icmp.type) {
    case ICMP_ECHOREPLY:
        PRINT_INFO(buf, mx + 1, "Echo reply:   id = 0x%x  seq = %d", info->icmp.echo.id, info->icmp.echo.seq_num);
        break;
    case ICMP_ECHO:
        PRINT_INFO(buf, mx + 1, "Echo request: id = 0x%x  seq = %d", info->icmp.echo.id, info->icmp.echo.seq_num);
        break;
    default:
        PRINT_INFO(buf, mx + 1, "Type: %d", info->icmp.type);
        break;
    }
}

void print_igmp(struct ip_info *info, char *buf)
{
    int mx, my;

    getmaxyx(wmain, my, mx);
    PRINT_PROTOCOL(buf, mx + 1, "IGMP");
    switch (info->igmp.type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        PRINT_INFO(buf, mx + 1, "Membership query  Max response time: %d seconds",
                        info->igmp.max_resp_time / 10);
        break;
    case IGMP_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, mx + 1, "Membership report");
        break;
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, mx + 1, "IGMP2 Membership report");
        break;
    case IGMP_HOST_LEAVE_MESSAGE:
        PRINT_INFO(buf, mx + 1, "Leave group");
        break;
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, mx + 1, "IGMP3 Membership report");
        break;
    default:
        PRINT_INFO(buf, mx + 1, "Type 0x%x", info->igmp.type);
        break;
    }
    PRINT_INFO(buf, mx + 1, "  Group address: %s", info->igmp.group_addr);
}
