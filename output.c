#include <arpa/inet.h>
#include <net/if_arp.h>
#include <string.h>
#include <netdb.h>
#include <linux/igmp.h>
#include "misc.h"
#include "output.h"
#include "list.h"
#include "error.h"

#define HEADER_HEIGHT 4
#define STATUS_HEIGHT 1
#define HOSTNAMELEN 255 /* maximum 255 according to rfc1035 */
#define ADDR_WIDTH 36
#define PROT_WIDTH 10

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

typedef node_t line;

static WINDOW *wheader;
static WINDOW *wmain;
static WINDOW *wstatus;
static int outy = 0;
static int interactive = 0;
static int numeric = 1;

/* keep a pointer to the top and bottom line */
static const line *top;
static const line *bottom;

static void print_header();
static void scroll_window();
static void print(char *buf);
static void gethost(char *addr, char *host, int hostlen);
static void print_udp(struct ip_info *info, char *buf);
static void print_igmp(struct ip_info *info, char *buf);
static void print_dns(struct ip_info *info, char *buf);
static int print_dns_class(char *buf, uint16_t class, int n);

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
        mvwprintw(wheader, y, 0, "Source");
        mvwprintw(wheader, y, ADDR_WIDTH, "Destination");
        mvwprintw(wheader, y, 2 * ADDR_WIDTH, "Protocol");
        mvwprintw(wheader, y, 2 * ADDR_WIDTH + PROT_WIDTH, "Info");
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
    print(buffer);
}

void print_ip(struct ip_info *info)
{
    char *buffer;

    buffer = malloc(COLS + 1);
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
        PRINT_PROTOCOL(buffer, "ICMP");
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
    print(buffer);
}

void print_udp(struct ip_info *info, char *buf)
{
    switch (info->udp.utype) {
    case DNS:
        print_dns(info, buf);
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
        case QUERY:
            n += PRINT_INFO(buf, n, "Standard query: ");
            switch (info->udp.dns.question.qtype) {
            case DNS_TYPE_PTR:
                n += PRINT_INFO(buf, n, "TYPE = PTR");
                break;
            default:
                n += PRINT_INFO(buf, n, "TYPE = %d", info->udp.dns.question.qtype);
                break;
            }
            n += print_dns_class(buf, info->udp.dns.question.qclass, n);
            PRINT_INFO(buf, n, "  QNAME = %s", info->udp.dns.question.qname);
            break;
        case IQUERY:
            PRINT_INFO(buf, n, "Inverse query");
            break;
        case STATUS:
            PRINT_INFO(buf, n, "Server status request");
            break;
        }
    } else {
        switch (info->udp.dns.rcode) {
        case NO_ERROR:
            n += PRINT_INFO(buf, n, "Response: ");
            break;
        case FORMAT_ERROR:
            PRINT_INFO(buf, n, "Response: format error");
            return;
        case SERVER_FAILURE:
            PRINT_INFO(buf, n, "Response: server failure");
            return;
        case NAME_ERROR:
            PRINT_INFO(buf, n, "Response: name error");
            return;
        case NOT_IMPLEMENTED:
            PRINT_INFO(buf, n, "Response: request not supported");
            return;
        case REFUSED:
            PRINT_INFO(buf, n, "Response: operation refused");
            return;
        }
        switch (info->udp.dns.answer.type) {
        case DNS_TYPE_A:
        {
            char addr[INET_ADDRSTRLEN];
            uint32_t haddr = htonl(info->udp.dns.answer.rdata.address);

            if (inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr)) == NULL) {
                err_msg("inet_ntop error");
            }
            n += PRINT_INFO(buf, n, "TYPE = A  %s", addr);
            break;
        }
        case DNS_TYPE_CNAME:
            n += PRINT_INFO(buf, n, "TYPE = CNAME  %s", info->udp.dns.answer.rdata.cname);
            break;
        case DNS_TYPE_PTR:
            n += PRINT_INFO(buf, n, "TYPE = PTR  %s", info->udp.dns.answer.rdata.ptrdname);
            break;
        default:
            n += PRINT_INFO(buf, n, "TYPE = %d", info->udp.dns.answer.type);
            break;
        }
        print_dns_class(buf, info->udp.dns.answer.class, n);
    }
}

int print_dns_class(char *buf, uint16_t class, int n)
{
    int num_chars = 0;

    switch (class) {
    case DNS_CLASS_IN:
        num_chars = PRINT_INFO(buf, n, "  CLASS = IN");
        break;
    case DNS_CLASS_CS:
        num_chars = PRINT_INFO(buf, n, "  CLASS = CS");
        break;
    case DNS_CLASS_CH:
        num_chars = PRINT_INFO(buf, n, "  CLASS = CH");
        break;
    case DNS_CLASS_HS:
        num_chars = PRINT_INFO(buf, n, "  CLASS = HS");
        break;
    default:
        break;
    }
    return num_chars;
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

/*
 * Get host name from addr, which is in dotted-decimal format. This will send a
 * DNS request over UDP.
 */
void gethost(char *addr, char *host, int hostlen)
{
    struct sockaddr_in saddr;
    struct in_addr naddr;

    inet_pton(AF_INET, addr, &naddr);
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr = naddr;
    getnameinfo((struct sockaddr *) &saddr, sizeof(struct sockaddr_in),
                host, hostlen, NULL, 0, 0);
}
