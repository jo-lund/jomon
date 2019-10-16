#include <ctype.h>
#include <string.h>
#include "hexdump.h"
#include "layout_int.h"
#include "../decoder/decoder.h"
#include "../util.h"
#include "../list.h"

#define HD_LIST_VIEW 0
#define HD_WINDOW 1
#define HD_NORMAL_LEN 76
#define HD_WIDE_LEN 75
#define HD_ASCII_IDX 60

// TODO: Remove this and make the elements modifiable
#define CYAN COLOR_PAIR(7)
#define GREEN COLOR_PAIR(3)
#define BLUE COLOR_PAIR(5)
#define MAGENTA COLOR_PAIR(6)
#define LIGHT_BLUE (BLUE | A_BOLD)
#define PURPLE (MAGENTA | A_BOLD)

typedef struct {
    int type;
    union {
        struct {
            list_view *lvw;
            list_view_header *header;
        };
        struct {
            WINDOW *win;
            struct packet *p;
            int y;
            int x;
        };
    } h_arg;
} hd_args;

enum hex_state {
    HD_ETHERNET,
    HD_ARP,
    HD_LLC,
    HD_IP,
    HD_IP6,
    HD_UDP,
    HD_TCP,
    HD_ICMP,
    HD_IGMP,
    HD_PIM,
    HD_APP,
    HD_SNAP,
    HD_STP,
    HD_UNKNOWN
};

static struct uint_string hex_state_val[] = {
    { HD_ETHERNET, "Ethernet" },
    { HD_ARP, "ARP" },
    { HD_LLC, "LLC" },
    { HD_IP, "IP" },
    { HD_IP6, "IP6" },
    { HD_UDP, "UDP" },
    { HD_TCP, "TCP" },
    { HD_ICMP, "ICMP" },
    { HD_IGMP, "IGMP" },
    { HD_PIM, "PIM" },
    { HD_SNAP, "SNAP" },
    { HD_STP, "STP" },
    { HD_UNKNOWN, "Data" }
};

static list_t *protocols;

static void print_hexdump(enum hexmode mode, unsigned char *payload, uint16_t len, hd_args *arg);
static enum hex_state get_next_state(enum hex_state cur_state, struct packet *p);
static void print_char(WINDOW *win, char *buf, enum hex_state *state, struct packet *p, int i, int j, bool update);
static void print_state(WINDOW *win, char *buf, enum hex_state state);
static enum hex_state str2enum(char *state);
static inline char *enum2str(enum hex_state state);

void add_hexdump(list_view *lw, list_view_header *header, enum hexmode mode, unsigned char *payload, uint16_t len)
{
    hd_args args;

    args.type = HD_LIST_VIEW;
    args.h_arg.lvw = lw;
    args.h_arg.header = header;
    print_hexdump(mode, payload, len, &args);
}

void add_winhexdump(WINDOW *win, int y, int x, enum hexmode mode, struct packet *p)
{
    hd_args args;

    args.type = HD_WINDOW;
    args.h_arg.win = win;
    args.h_arg.p = p;
    args.h_arg.y = y;
    args.h_arg.x = x;
    print_hexdump(mode, p->eth.data, p->eth.payload_len + ETH_HLEN, &args);
}

void print_hexdump(enum hexmode mode, unsigned char *payload, uint16_t len, hd_args *arg)
{
    int size = 1024;
    int num = 0;
    char buf[size];
    int hexoffset;
    char *hex = "0123456789abcdef";
    char *offset = " offset ";
    enum hex_state state = HD_ETHERNET;
    enum hex_state prev_state = state;

    protocols = list_init(NULL);
    list_push_back(protocols, enum2str(state));

    if (mode == HEXMODE_WIDE) {
        hexoffset = 64;
        snprintf(buf, size, "%-11s%s%s%s%s", offset, hex, hex, hex, hex);
    } else {
        hexoffset = 16;
        snprintf(buf, size, "%-11s0  1  2  3  4  5  6  7", offset);
        if (arg->type == HD_LIST_VIEW) {
            snprintcat(buf, size, "   8  9  a  b  c  d  e  f  %s", hex);
        } else {
            snprintcat(buf, size, "   8  9  a  b  c  d  e  f   %s", hex);
        }
    }
    if (arg->type == HD_LIST_VIEW) {
        list_view_item *item;

        item = LV_ADD_TEXT_ELEMENT(arg->h_arg.lvw, arg->h_arg.header, "%s", buf);
        item->attr = A_BOLD;
    } else {
        printat(arg->h_arg.win, arg->h_arg.y, arg->h_arg.x, A_BOLD, "%s", buf);
    }

    while (num < len) {
        snprintf(buf, size, "%08x  ", num);
        if (mode == HEXMODE_NORMAL) {
            for (int i = num; i < num + hexoffset; i++) {
                if (i < len) {
                    snprintcat(buf, size, "%02x ", payload[i]);
                } else {
                    snprintcat(buf, size, "   ");
                }
                if (i % hexoffset - 7 == 0) snprintcat(buf, size, " ");
            }
        }
        snprintcat(buf, size, " ");
        for (int i = num; i < num + hexoffset; i++) {
            if (i < len) {
                if (isprint(payload[i])) {
                    snprintcat(buf, size, "%c", payload[i]);
                } else {
                    snprintcat(buf, size, ".");
                }
            } else {
                snprintcat(buf, size, " ");
            }
        }
        if (arg->type == HD_LIST_VIEW) {
            LV_ADD_TEXT_ELEMENT(arg->h_arg.lvw, arg->h_arg.header, "%s", buf);
        } else {
            int i = 0;
            int x = arg->h_arg.x;
            int j = num;

            /* print offset */
            arg->h_arg.y++;
            while (i < 8) {
                mvwaddch(arg->h_arg.win, arg->h_arg.y, x++, buf[i]);
                i++;
            }

            if (mode == HEXMODE_NORMAL) {
                int k = 0;

                /* print hex values */
                while (i < HD_ASCII_IDX) {
                    if (isspace(buf[i])) {
                        waddch(arg->h_arg.win, buf[i]);
                    } else {
                        print_char(arg->h_arg.win, buf, &state, arg->h_arg.p, i, j, true);
                        if (k % 2) j++;
                        k++;
                    }
                    i++;
                }
                j = num;

                /* print ascii */
                waddch(arg->h_arg.win, ACS_VLINE);
                while (i < HD_NORMAL_LEN) {
                    if (isspace(buf[i])) {
                        waddch(arg->h_arg.win, buf[i]);
                    } else {
                        print_char(arg->h_arg.win, buf, &prev_state, arg->h_arg.p, i, j++, false);
                    }
                    i++;
                }
                waddch(arg->h_arg.win, ACS_VLINE);
            } else { /* wide hex mode -- only print ascii */
                j = num;
                while (i < HD_WIDE_LEN) {
                    if (isspace(buf[i])) {
                        waddch(arg->h_arg.win, buf[i]);
                    } else {
                        print_char(arg->h_arg.win, buf, &prev_state, arg->h_arg.p, i, j++, true);
                    }
                    i++;
                }
            }

            const node_t *n = list_begin(protocols);
            while (n) {
                char *str;

                str = (char *) list_data(n);
                print_state(arg->h_arg.win, str, str2enum(str));
                n = list_next(n);
            }
            list_clear(protocols, NULL);
        }
        num += hexoffset;
    }
    list_free(protocols, NULL);
}

// TODO: This needs to be cleaned up
void print_char(WINDOW *win, char *buf, enum hex_state *state, struct packet *p, int i, int j, bool update)
{
check_state:
    switch (*state) {
    case HD_ETHERNET:
        if (j >= ETH_HLEN) {
            *state = get_next_state(*state, p);
            if (update) {
                list_push_back(protocols, enum2str(*state));
            }
            goto check_state;
        }
        waddch(win, buf[i] | PURPLE);
        break;
    case HD_ARP:
        waddch(win, buf[i] | GREEN | A_BOLD);
        break;
    case HD_LLC:
        if (j >= ETH_HLEN + LLC_HDR_LEN) {
            *state = get_next_state(*state, p);
            if (update) {
                list_push_back(protocols, enum2str(*state));
            }
            goto check_state;
        }
        waddch(win, buf[i] | LIGHT_BLUE);
        break;
    case HD_IP:
        if (j >= ETH_HLEN + p->eth.ipv4->ihl * 4) {
            *state = get_next_state(*state, p);
            if (update) {
                list_push_back(protocols, enum2str(*state));
            }
            goto check_state;
        }
        waddch(win, buf[i] | LIGHT_BLUE);
        break;
    case HD_IP6:
        /* TDOO: should include extension headers */
        if (j >= ETH_HLEN + IPV6_FIXED_HEADER_LEN) {
            *state = get_next_state(*state, p);
            if (update) {
                list_push_back(protocols, enum2str(*state));
            }
            goto check_state;
        }
        waddch(win, buf[i] | LIGHT_BLUE);
        break;
    case HD_UDP:
        if (p->eth.ethertype == ETH_P_IP) {
            if (j >= ETH_HLEN + p->eth.ipv4->ihl * 4 + UDP_HDR_LEN) {
                *state = get_next_state(*state, p);
                if (update) {
                    struct protocol_info *pinfo = get_protocol(get_adu_info(p)->utype);

                    if (pinfo)
                        list_push_back(protocols, pinfo->short_name);
                }
                goto check_state;
            }
        } else { /* TODO: need to check for IPV6 extension headers */
            if (j >= ETH_HLEN + IPV6_FIXED_HEADER_LEN + UDP_HDR_LEN) {
                *state = get_next_state(*state, p);
                if (update) {
                    struct protocol_info *pinfo = get_protocol(get_adu_info(p)->utype);

                    if (pinfo)
                        list_push_back(protocols, pinfo->short_name);
                }
                goto check_state;
            }
        }
        waddch(win, buf[i]);
        break;
    case HD_TCP:
        if (p->eth.ethertype == ETH_P_IP) {
            if (j >= ETH_HLEN + p->eth.ipv4->ihl * 4 + TCP_HDR_LEN(p)) {
                *state = HD_APP;
                if (update) {
                    struct protocol_info *pinfo = get_protocol(get_adu_info(p)->utype);

                    if (pinfo)
                        list_push_back(protocols, pinfo->short_name);
                }
                goto check_state;
            }
        } else { /* TODO: need to check for IPV6 extension headers */
            if (j >= ETH_HLEN + IPV6_FIXED_HEADER_LEN + TCP_HDR_LEN(p)) {
                *state = HD_APP;
                if (update) {
                    struct protocol_info *pinfo = get_protocol(get_adu_info(p)->utype);

                    if (pinfo)
                        list_push_back(protocols, pinfo->short_name);
                }
                goto check_state;
            }
        }
        waddch(win, buf[i]);
        break;
    default:
        waddch(win, buf[i] | GREEN | A_BOLD);
        break;
    }
}

enum hex_state get_next_state(enum hex_state cur_state, struct packet *p)
{
    enum hex_state next_state = HD_UNKNOWN;

    switch (cur_state) {
    case HD_ETHERNET:
        if (p->eth.ethertype <= ETH_802_3_MAX) {
            next_state = HD_LLC;
        } else {
            switch (p->eth.ethertype) {
            case ETH_P_ARP:
                next_state = HD_ARP;
                break;
            case ETH_P_IP:
                next_state = HD_IP;
                break;
            case ETH_P_IPV6:
                next_state = HD_IP6;
                break;
            default:
                break;
            }
        }
        break;
    case HD_LLC:
    {
        enum eth_802_type type = get_eth802_type(p->eth.llc);

        switch (type) {
        case ETH_802_STP:
            next_state = HD_STP;
            break;
        case ETH_802_SNAP:
            next_state = HD_SNAP;
            break;
        default:
            break;
        }
        break;
    }
    case HD_IP:
    case HD_IP6:
    {
        uint8_t protocol;

        if (p->eth.ethertype == ETH_P_IP) {
            protocol = p->eth.ipv4->protocol;
        } else {
            protocol = p->eth.ipv6->next_header;
        }

        switch (protocol) {
        case IPPROTO_UDP:
            next_state = HD_UDP;
            break;
        case IPPROTO_TCP:
            next_state = HD_TCP;
            break;
        case IPPROTO_ICMP:
            next_state = HD_ICMP;
            break;
        case IPPROTO_IGMP:
            next_state = HD_IGMP;
            break;
        case IPPROTO_PIM:
            next_state = HD_PIM;
            break;
        default:
            break;
        }
        break;
    }
    default:
        break;
    }
    return next_state;
}

void print_state(WINDOW *win, char *buf, enum hex_state state)
{
    switch (state) {
    case HD_ETHERNET:
        printat(win, -1, -1, PURPLE, "  %s", buf);
        break;
    case HD_LLC:
    case HD_IP:
    case HD_IP6:
        printat(win, -1, -1, LIGHT_BLUE, "  %s", buf);
        break;
    case HD_UDP:
    case HD_TCP:
        wprintw(win, "  %s", buf);
        break;
    default:
        printat(win, -1, -1, GREEN | A_BOLD, "  %s", buf);
        break;
    }
}

enum hex_state str2enum(char *state)
{
    for (unsigned int i = 0; i < ARRAY_SIZE(hex_state_val); i++) {
        if (!strcmp(hex_state_val[i].str, state)) {
            return hex_state_val[i].val;
        }
    }
    return HD_UNKNOWN;
}

inline char *enum2str(enum hex_state state)
{
    return hex_state_val[state].str;
}
