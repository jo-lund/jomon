#include <arpa/inet.h>
#include <net/if_arp.h>
#include <string.h>
#include <netdb.h>
#include <linux/igmp.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
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
static void print_icmp(struct ip_info *info, char *buf);
static void print_igmp(struct ip_info *info, char *buf);
static void print_dns(struct ip_info *info, char *buf);
static int print_dns_class(char *buf, uint16_t class, int n);
static int print_dns_type(struct ip_info *info, char *buf, uint16_t type, int n);
static void print_nbns(struct ip_info *info, char *buf);
static int print_nbns_opcode(char *buf, uint8_t opcode, int n);
static int print_nbns_type(char *buf, uint8_t type, int n);
static int print_nbns_record(struct ip_info *info, char *buf, int n);

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
        kill(0, SIGINT);
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
    print(buffer);
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
