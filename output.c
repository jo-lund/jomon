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
#define MAXLINE 1000

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define PRINT_SOURCE(buffer, src) snprintf(buffer, COLS + 1, "%-" STR(ADDR_WIDTH) "s", src)
#define PRINT_DEST(buffer, dst) \
    snprintf(buffer + ADDR_WIDTH, COLS + 1 - ADDR_WIDTH, "%-" STR(ADDR_WIDTH) "s", dst)
#define PRINT_PROTOCOL(buffer, prot) \
    snprintf(buffer + 2 * ADDR_WIDTH, COLS + 1 - 2 * ADDR_WIDTH, "%-" STR(PROT_WIDTH) "s", prot)
#define PRINT_INFO(buffer, n, fmt, ...)                               \
    snprintf(buffer + 2 * ADDR_WIDTH + PROT_WIDTH + n, COLS + 1 - (2 * ADDR_WIDTH + PROT_WIDTH) - n, fmt, ## __VA_ARGS__)
#define PRINT_LINE(buffer, src, dst, prot, fmt, ...) \
    do {                                             \
        PRINT_SOURCE(buffer, src);                   \
        PRINT_DEST(buffer, dst);                     \
        PRINT_PROTOCOL(buffer, prot);                \
        PRINT_INFO(buffer, 0, fmt, ## __VA_ARGS__);  \
    } while (0)

static WINDOW *wheader;
static WINDOW *wmain;
static WINDOW *wstatus;
static WINDOW *wsub_main; /* sub window of wmain */

static int outy = 0;
static int interactive = 0;
static int numeric = 1;
static int screen_line = 0;

static void print_header();
static void scroll_window();
static void print(char *buf, int key);
static void print_arp(char *buffer, struct arp_info *info);
static void print_ip(char *buffer, struct ip_info *info);
static void print_udp(struct ip_info *info, char *buf);
static void print_icmp(struct ip_info *info, char *buf);
static void print_igmp(struct ip_info *info, char *buf);
static void print_dns(struct ip_info *info, char *buf);
static int print_dns_class(char *buf, uint16_t class, int n);
static int print_dns_type(struct ip_info *info, char *buf, uint16_t type, int n);
static void print_nbns(struct ip_info *info, char *buf);
static int print_nbns_opcode(char *buf, uint8_t opcode, int n);
static int print_nbns_type(char *buf, uint8_t type, int n);
static int print_nbns_record(struct ip_info *info, char *buf, int n);

static void print_information(int lineno, bool select);
static void print_arp_verbose(struct arp_info *info);
static void print_ip_verbose(struct ip_info *info);
static void print_udp_verbose(struct ip_info *info);
static void print_dns_verbose(struct dns_info *info);

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
    wheader = newwin(HEADER_HEIGHT, COLS, 0, 0);
    wmain = newwin(LINES - HEADER_HEIGHT - STATUS_HEIGHT, COLS, HEADER_HEIGHT, 0);
    wstatus = newwin(STATUS_HEIGHT, COLS, LINES - STATUS_HEIGHT, 0);
    nodelay(wmain, TRUE); /* input functions must be non-blocking */
    keypad(wmain, TRUE);
    print_header();
    scrollok(wmain, TRUE); /* enable scrolling */
}

/* scroll the window if necessary */
void scroll_window()
{
    if (outy >= LINES - HEADER_HEIGHT - STATUS_HEIGHT) {
        outy = LINES - HEADER_HEIGHT - STATUS_HEIGHT - 1;
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
            if (outy >= LINES - HEADER_HEIGHT - STATUS_HEIGHT) {
                struct packet p;
                int y, x;
                unsigned char *buf;
                int c = vector_size() - 1;

                getmaxyx(wmain, y, x);
                werase(wmain);
                list_clear();

                /* print the new lines stored in vector from bottom to top of screen */
                for (int i = y - 1; i >= 0; i--, c--) {
                    char *buffer;

                    buf = vector_get_data(c);
                    handle_ethernet(buf, &p); /* deserialize packet */
                    buffer = alloc_print_buffer(&p, x + 1);
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
            int y, x;
            int lineno;

            interactive = 1;
            mvwprintw(wstatus, 0, 0, "(interactive)");
            wrefresh(wstatus);
            getmaxyx(wmain, y, x);
            lineno = vector_size() - 1; /* bottom line number */
            selection_line = lineno - (y - 1); /* top line on screen */
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
        int x, y;

        getmaxyx(wmain, y, x);

        if (selection_line > 0 && screen_line == 0) {
            unsigned char *buf;
            struct packet p;
            char *buffer;

            selection_line--;
            list_pop_back();
            wscrl(wmain, -1);
            buf = vector_get_data(selection_line);
            handle_ethernet(buf, &p); /* deserialize packet */
            buffer = alloc_print_buffer(&p, x + 1);
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
        int x, y;

        getmaxyx(wmain, y, x);

        /* scroll screen if the selection bar is at the bottom */
        if (screen_line == y - 1) {
            if (selection_line + 1 > vector_size()) return;
            unsigned char *buf = vector_get_data(++selection_line);
            struct packet p;

            if (buf) {
                char *buffer;

                list_pop_front();
                wscrl(wmain, 1);
                handle_ethernet(buf, &p); /* deserialize packet */
                buffer = alloc_print_buffer(&p, x + 1);
                print(buffer, KEY_DOWN);

                /* deselect previous line and highlight next line at bottom */
                mvwchgat(wmain, y - 2, 0, -1, A_NORMAL, 0, NULL);
                mvwchgat(wmain, y - 1, 0, -1, A_NORMAL, 1, NULL);
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
    const node_t *l = list_ith(screen_line + 1);

    /* make space for protocol specific information */
    wsub_main = derwin(wmain, num_lines, COLS, screen_line + 1, 0);
    wclrtobot(wsub_main);
    wrefresh(wsub_main);

    outy = screen_line + num_lines + 1;
    /* print the remaining lines on the screen below the sub window */
    while (l) {
        mvwprintw(wmain, outy++, 0, "%s", (char *) list_data(l));
        l = list_next(l);
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

    /* number of resource records */
    while (i < 4) {
        records += info->section_count[i++];
    }
    create_subwindow(11 + records);
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
        char buffer[MAXLINE];

        i = 0;
        mvwprintw(wsub_main, ++y, 4, "Resource records:");
        while (records--) {
            int n = 0;
            int namelen;

            n += snprintf(buffer, MAXLINE, "%s\t", info->record[i].name);
            n += snprintf(buffer + n, MAXLINE - n, "%-6s", get_dns_class(info->record[i].class));
            n += snprintf(buffer + n, MAXLINE - n, "%-8s", get_dns_type(info->record[i].type));
            switch (info->record[i].type) {
            case DNS_TYPE_A:
            {
                char addr[INET_ADDRSTRLEN];
                uint32_t haddr = htonl(info->record[i].rdata.address);

                inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr));
                n += snprintf(buffer + n, MAXLINE - n, "%s", addr);
                break;
            }
            case DNS_TYPE_NS:
                n += snprintf(buffer + n, MAXLINE - n, "%s", info->record[i].rdata.nsdname);
                break;
            case DNS_TYPE_CNAME:
                n += snprintf(buffer + n, MAXLINE - n, "%s", info->record[i].rdata.cname);
                break;
            case DNS_TYPE_PTR:
                n += snprintf(buffer + n, MAXLINE - n, "%s", info->record[i].rdata.ptrdname);
                break;
            default:
                n += snprintf(buffer + n, MAXLINE - n, "type: %d", info->record[i].type);
                break;
            }
            mvwprintw(wsub_main, ++y, 8, "%s", buffer);
            i++;
        }
    }
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
    int y, x;

    getmaxyx(wmain, y, x);
    buffer = alloc_print_buffer(p, x + 1);
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
    switch (key) {
    case KEY_UP:
        list_push_front(buf);
        mvwprintw(wmain, 0, 0, "%s", buf);
        wrefresh(wmain);
        break;
    case KEY_DOWN:
        list_push_back(buf);
        mvwprintw(wmain, LINES - HEADER_HEIGHT - STATUS_HEIGHT - 1, 0, "%s", buf);
        wrefresh(wmain);
        break;
    default: /* new packet from the network interface */
        if (!interactive || (interactive && outy < LINES - HEADER_HEIGHT - STATUS_HEIGHT)) {
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
    switch (info->op) {
    case ARPOP_REQUEST:
        PRINT_LINE(buffer, info->sip, info->tip, "ARP",
                   "Request: Looking for hardware address of %s", info->tip);
        break;
    case ARPOP_REPLY:
        PRINT_LINE(buffer, info->sip, info->tip, "ARP",
                   "Reply: %s has hardware address %s", info->sip, info->sha);
        break;
    default:
        PRINT_LINE(buffer, info->sip, info->tip, "ARP", "Opcode %d", info->op);
        break;
    }
}

/* print IP packet information */
void print_ip(char *buffer, struct ip_info *info)
{
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
        PRINT_SOURCE(buffer, sname);
        PRINT_DEST(buffer, dname);
    } else {
        PRINT_SOURCE(buffer, info->src);
        PRINT_DEST(buffer, info->dst);
    }
    switch (info->protocol) {
    case IPPROTO_ICMP:
        print_icmp(info, buffer);
        break;
    case IPPROTO_IGMP:
        print_igmp(info, buffer);
        break;
    case IPPROTO_TCP:
        PRINT_PROTOCOL(buffer, "TCP");
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
        PRINT_PROTOCOL(buf, "UDP");
        PRINT_INFO(buf, 0, "Source port: %d  Destination port: %d", info->udp.src_port,
                   info->udp.dst_port);
        break;
    }
}

void print_dns(struct ip_info *info, char *buf)
{
    int n = 0;

    PRINT_PROTOCOL(buf, "DNS");
    if (info->udp.dns.qr == 0) {
        switch (info->udp.dns.opcode) {
        case DNS_QUERY:
            n += PRINT_INFO(buf, n, "Standard query: ");
            n += print_dns_type(info, buf, info->udp.dns.question.qtype, n);
            n += PRINT_INFO(buf, n, " %s", info->udp.dns.question.qname);
            n += print_dns_class(buf, info->udp.dns.question.qclass, n);
            break;
        case DNS_IQUERY:
            PRINT_INFO(buf, n, "Inverse query");
            break;
        case DNS_STATUS:
            PRINT_INFO(buf, n, "Server status request");
            break;
        }
    } else {
        switch (info->udp.dns.rcode) {
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
            n += PRINT_INFO(buf, n, "Response: ");
            break;
        }
        n += print_dns_type(info, buf, info->udp.dns.record[0].type, n);
        print_dns_class(buf, info->udp.dns.record[0].class, n);
    }
}

int print_dns_type(struct ip_info *info, char *buf, uint16_t type, int n)
{
    int num_chars = 0;

    switch (type) {
    case DNS_TYPE_A:
    {
        num_chars += PRINT_INFO(buf, n, "A");
        if (info->udp.dns.qr) {
            char addr[INET_ADDRSTRLEN];
            uint32_t haddr = htonl(info->udp.dns.record[0].rdata.address);

            if (inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr)) == NULL) {
                err_msg("inet_ntop error");
            }
            num_chars += PRINT_INFO(buf, n + num_chars, " %s", addr);
        }
        break;
    }
    case DNS_TYPE_NS:
        num_chars += PRINT_INFO(buf, n, "NSDNAME");
        if (info->udp.dns.qr) {
            num_chars += PRINT_INFO(buf, n + num_chars, " %s", info->udp.dns.record[0].rdata.nsdname);
        }
        break;
    case DNS_TYPE_CNAME:
        num_chars += PRINT_INFO(buf, n, "CNAME");
        if (info->udp.dns.qr) {
            num_chars += PRINT_INFO(buf, n + num_chars, " %s", info->udp.dns.record[0].rdata.cname);
        }
        break;
    case DNS_TYPE_PTR:
        num_chars += PRINT_INFO(buf, n, "PTR");
        if (info->udp.dns.qr) {
            num_chars += PRINT_INFO(buf, n + num_chars, " %s", info->udp.dns.record[0].rdata.ptrdname);
        }
        break;
    default:
        num_chars += PRINT_INFO(buf, n, "TYPE = %d", type);
        break;
    }
    return num_chars;
}

int print_dns_class(char *buf, uint16_t class, int n)
{
    int num_chars = 0;

    switch (class) {
    case DNS_CLASS_IN:
        num_chars = PRINT_INFO(buf, n, " IN");
        break;
    case DNS_CLASS_CS:
        num_chars = PRINT_INFO(buf, n, " CS");
        break;
    case DNS_CLASS_CH:
        num_chars = PRINT_INFO(buf, n, " CH");
        break;
    case DNS_CLASS_HS:
        num_chars = PRINT_INFO(buf, n, " HS");
        break;
    default:
        break;
    }
    return num_chars;
}

void print_nbns(struct ip_info *info, char *buf)
{
    int n = 0;

    PRINT_PROTOCOL(buf, "NBNS");
    if (info->udp.nbns.r == 0) {
        n += print_nbns_opcode(buf, info->udp.nbns.opcode, n);
        n += PRINT_INFO(buf, n, " request:");
        n += print_nbns_type(buf, info->udp.nbns.question.qtype, n);
        n += PRINT_INFO(buf, n, " %s", info->udp.nbns.question.qname);
        if (info->udp.nbns.rr) {
            print_nbns_record(info, buf, n);
        }
    } else {
        switch (info->udp.nbns.rcode) {
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
        n += print_nbns_opcode(buf, info->udp.nbns.opcode, n);
        n += PRINT_INFO(buf, n, " response:");
        n += print_nbns_type(buf, info->udp.nbns.record[0].rrtype, n);
        n += PRINT_INFO(buf, n, " %s", info->udp.nbns.record[0].rrname);
        print_nbns_record(info, buf, n);
    }
}

int print_nbns_opcode(char *buf, uint8_t opcode, int n)
{
    int num_chars = 0;

    switch (opcode) {
    case NBNS_QUERY:
        num_chars += PRINT_INFO(buf, n, "Name query");
        break;
    case NBNS_REGISTRATION:
        num_chars += PRINT_INFO(buf, n, "Name registration");
        break;
    case NBNS_REFRESH:
        num_chars += PRINT_INFO(buf, n, "Name refresh");
        break;
    default:
        num_chars += PRINT_INFO(buf, n, "Opcode: %d", opcode);
        break;
    }
    return num_chars;
}

int print_nbns_type(char *buf, uint8_t type, int n)
{
    int num_chars = 0;

    switch (type) {
    case NBNS_NB:
        num_chars += PRINT_INFO(buf, n, " NB");
        break;
    case NBNS_NBSTAT:
        num_chars += PRINT_INFO(buf, n, " Node status request");
        break;
    default:
        num_chars += PRINT_INFO(buf, n, " TYPE = %d", type);
        break;
    }
    return num_chars;
}

int print_nbns_record(struct ip_info *info, char *buf, int n)
{
    int num_chars = 0;

    switch (info->udp.nbns.record[0].rrtype) {
    case NBNS_NB:
    {
        if (info->udp.nbns.record[0].rdata.nb.g) {
            num_chars += PRINT_INFO(buf, n, "  Group NetBIOS name");
        } else {
            num_chars += PRINT_INFO(buf, n, "  Unique NetBIOS name");
        }
        char addr[INET_ADDRSTRLEN];
        uint32_t haddr = htonl(info->udp.nbns.record[0].rdata.nb.address[0]);

        if (inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr)) == NULL) {
            err_msg("inet_ntop error");
        }
        num_chars += PRINT_INFO(buf, n + num_chars, " %s", addr);
        break;
    }
    case NBNS_NS:
        num_chars += PRINT_INFO(buf, n, " NSD Name: %s", info->udp.nbns.record[0].rdata.nsdname);
        break;
    case NBNS_A:
    {
        char addr[INET_ADDRSTRLEN];
        uint32_t haddr = htonl(info->udp.nbns.record[0].rdata.nsdipaddr);

        if (inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr)) == NULL) {
            err_msg("inet_ntop error");
        }
        num_chars += PRINT_INFO(buf, n, " NSD IP address: %s", addr);
        break;
    }
    case NBNS_NBSTAT:
        num_chars += PRINT_INFO(buf, n, "NBSTAT");
        break;
    default:
        break;
    }
    return num_chars;
}

void print_icmp(struct ip_info *info, char *buf)
{
    int n = 0;

    PRINT_PROTOCOL(buf, "ICMP");
    switch (info->icmp.type) {
    case ICMP_ECHOREPLY:
        PRINT_INFO(buf, n, "Echo reply:   id = 0x%x  seq = %d", info->icmp.echo.id, info->icmp.echo.seq_num);
        break;
    case ICMP_ECHO:
        PRINT_INFO(buf, n, "Echo request: id = 0x%x  seq = %d", info->icmp.echo.id, info->icmp.echo.seq_num);
        break;
    default:
        PRINT_INFO(buf, n, "Type: %d", info->icmp.type);
        break;
    }
}

void print_igmp(struct ip_info *info, char *buf)
{
    int n = 0;

    PRINT_PROTOCOL(buf, "IGMP");
    switch (info->igmp.type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        n += PRINT_INFO(buf, n, "Membership query  Max response time: %d seconds",
                        info->igmp.max_resp_time / 10);
        break;
    case IGMP_HOST_MEMBERSHIP_REPORT:
        n += PRINT_INFO(buf, n, "Membership report");
        break;
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
        n += PRINT_INFO(buf, n, "IGMP2 Membership report");
        break;
    case IGMP_HOST_LEAVE_MESSAGE:
        n += PRINT_INFO(buf, n, "Leave group");
        break;
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
        n += PRINT_INFO(buf, n, "IGMP3 Membership report");
        break;
    default:
        n += PRINT_INFO(buf, n, "Type 0x%x", info->igmp.type);
        break;
    }
    PRINT_INFO(buf, n, "  Group address: %s", info->igmp.group_addr);
}
