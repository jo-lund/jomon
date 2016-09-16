#include <string.h>
#include <signal.h>
#include <linux/igmp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include "misc.h"
#include "ui_layout.h"
#include "ui_protocols.h"
#include "list.h"
#include "error.h"
#include "util.h"
#include "vector.h"

#define HEADER_HEIGHT 4
#define STATUS_HEIGHT 1
#define KEY_ESC 27
#define ETH_WINSIZE 5
#define ARP_WINSIZE 10
#define IP_WINSIZE 14
#define TCP_WINSIZE 11
#define UDP_WINSIZE 6
#define IGMP_WINSIZE 6

static struct preferences {
    bool link_selected;
    bool link_arp_selected;
    bool link_llc_selected;
    bool link_stp_selected;
    bool network_selected;
    bool transport_selected;
    bool application_selected;
} preferences;

enum header_type {
    NONE,
    ETHERNET_HDR,
    ARP_HDR,
    LLC_HDR,
    STP_HDR,
    IP_HDR,
    UDP_HDR,
    TCP_HDR,
    IGMP_HDR,
    ICMP_HDR,
    APP_HDR
};

static struct line_info {
    bool selectable;
    bool selected;
    char *text;
    enum header_type type;
} *line;

static struct subwin_info {
    WINDOW *win;
    unsigned int top;
    unsigned int num_lines;
    struct line_info *line;
} subwindow;

extern vector_t *vector;
bool numeric = true;
static WINDOW *wheader;
static WINDOW *wmain;
static WINDOW *wstatus;
static int outy = 0;
static bool interactive = false;
static int selection_line = 0;
static int top = 0; /* index to top of screen */
static bool capturing = true;

/* the number of lines to be scrolled in order to print verbose packet information */
static int scrollvy = 0;

static void set_interactive(bool interactive_mode, int lines, int cols);
static bool check_line(int lines);
static void handle_keydown(int lines, int cols);
static void handle_keyup(int lines, int cols);
static void scroll_page(int lines, int cols);
static void scroll_window();
static int print_lines(int from, int to, int y, int cols);
static void print(char *buf);
static void print_header();
static void create_subwindow(int num_lines, int lineno);
static void delete_subwindow();
static bool update_subwin_selection(int lineno);
static void set_subwindow_line(int i, char *text, bool selected, enum header_type type);
static int calculate_subwin_size(struct packet *p, int screen_line);
static int calculate_applayer_size(struct application_info *info, int screen_line);
static void create_sublines(struct packet *p, int size);
static void create_app_sublines(struct packet *p, int i);
static void print_selected_packet();
static void print_protocol_information(struct packet *p, int lineno);
static void print_app_protocol(struct application_info *info, int y);

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
    memset(&subwindow, 0, sizeof(struct subwin_info));
    memset(&preferences, 0, sizeof(struct preferences));
}

void end_ncurses()
{
    endwin(); /* end curses mode */
    free(line);
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
    line = calloc(my, sizeof(struct line_info));
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
            print_selected_packet();
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

    if (subwindow.win) {
        num_lines += subwindow.num_lines - 1;
    }
    if (selection_line < vector_size(vector) + num_lines - 1) {
        return true;
    }
    return false;
}

void handle_keyup(int lines, int cols)
{
    if (!interactive) {
        set_interactive(true, lines, cols);
    }

    /* scroll screen if the selection bar is at the top */
    if (top && selection_line == top) {
        struct packet *p = vector_get_data(vector, --selection_line);

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
        struct packet *p = vector_get_data(vector, ++selection_line);

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
    if (!interactive) {
        set_interactive(true, lines, cols);
    }
    if (lines > 0) { /* scroll page down */
        if (vector_size(vector) <= lines) {
            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 0, NULL);
            selection_line = vector_size(vector) - 1;
            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 1, NULL);
        } else {
            int bottom = top + lines - 1;

            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 0, NULL);
            selection_line += lines;
            if (bottom + lines > vector_size(vector) - 1) {
                int scroll = vector_size(vector) - bottom - 1;

                wscrl(wmain, scroll);
                top += scroll;
                if (selection_line >= vector_size(vector)) {
                    selection_line = vector_size(vector) - 1;
                }
                print_lines(bottom + 1, vector_size(vector), vector_size(vector) - scroll - top, cols);
            } else {
                top += lines;
                wscrl(wmain, lines);
                print_lines(top, top + lines, 0, cols);
            }
            mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 1, NULL);
        }
    } else { /* scroll page up */
        if (vector_size(vector) <= abs(lines)) {
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
    if (!vector_size(vector)) return;

    if (interactive_mode) {
        interactive = true;
        mvwprintw(wstatus, 0, 0, "(interactive)");
        wrefresh(wstatus);
        selection_line = top;

        /* print selection bar */
        mvwchgat(wmain, 0, 0, -1, A_NORMAL, 1, NULL);
        wrefresh(wmain);
    } else {
        if (outy >= lines && capturing) {
            int c = vector_size(vector) - 1;

            werase(wmain);

            /* print the new lines stored in vector from bottom to top of screen */
            for (int i = lines - 1; i >= 0; i--, c--) {
                struct packet *p;
                char buffer[cols];

                p = vector_get_data(vector, c);
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

        p = vector_get_data(vector, from);
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
        mvwprintw(wheader, y, 0, "Number");
        mvwprintw(wheader, y, NUM_WIDTH, "Source");
        mvwprintw(wheader, y, ADDR_WIDTH + NUM_WIDTH, "Destination");
        mvwprintw(wheader, y, 2 * ADDR_WIDTH + NUM_WIDTH, "Protocol");
        mvwprintw(wheader, y, 2 * ADDR_WIDTH + PROT_WIDTH + NUM_WIDTH, "Info");
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

void print_file()
{
    int my = getmaxy(wmain);

    capturing = false;
    for (int i = 0; i < vector_size(vector) && i < my; i++) {
        print_packet(vector_get_data(vector, i));
    }
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
    subwindow.line = calloc(num_lines, sizeof(struct line_info));
    subwindow.win = derwin(wmain, num_lines, mx, start_line + 1, 0);
    subwindow.top = start_line + 1;
    subwindow.num_lines = num_lines;
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
    delwin(subwindow.win);
    subwindow.win = NULL;
    if (subwindow.line) {
        free(subwindow.line);
        subwindow.line = NULL;
    }
    subwindow.num_lines = 0;
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

void create_sublines(struct packet *p, int size)
{
    int i = 0;

    if (preferences.link_selected) {
        if (p->eth.ethertype < ETH_P_802_3_MIN) {
            set_subwindow_line(i, "- Ethernet 802.3", true, ETHERNET_HDR);
        } else {
            set_subwindow_line(i, "- Ethernet II", true, ETHERNET_HDR);
        }
        i += ETH_WINSIZE;
    } else {
        if (p->eth.ethertype < ETH_P_802_3_MIN) {
            set_subwindow_line(i, "+ Ethernet 802.3", false, ETHERNET_HDR);
        } else {
            set_subwindow_line(i, "+ Ethernet II", false, ETHERNET_HDR);
        }
        i++;
    }
    if (p->eth.ethertype == ETH_P_ARP) {
        if (preferences.link_arp_selected) {
            set_subwindow_line(i, "- Address Resolution Protocol (ARP)", true, ARP_HDR);
        } else {
            set_subwindow_line(i, "+ Address Resolution Protocol (ARP)", false, ARP_HDR);
            i++;
        }
    } else if (p->eth.ethertype == ETH_P_IP) {
        if (preferences.network_selected) {
            set_subwindow_line(i, "- Internet Protocol (IP)", true, IP_HDR);
            i += IP_WINSIZE;
        } else {
            set_subwindow_line(i, "+ Internet Protocol (IP)", false, IP_HDR);
            i++;
        }
        switch (p->eth.ip->protocol) {
        case IPPROTO_TCP:
            if (preferences.transport_selected) {
                set_subwindow_line(i, "- Transmission Control Protocol (TCP)", true, TCP_HDR);
                i += TCP_WINSIZE;
            } else {
                set_subwindow_line(i, "+ Transmission Control Protocol (TCP)", false, TCP_HDR);
                i++;
            }
            create_app_sublines(p, i);
            break;
        case IPPROTO_UDP:
            if (preferences.transport_selected) {
                set_subwindow_line(i, "- User Datagram Protocol (UDP)", true, UDP_HDR);
                i += UDP_WINSIZE;
            } else {
                set_subwindow_line(i, "+ User Datagram Protocol (UDP)", false, UDP_HDR);
                i++;
            }
            create_app_sublines(p, i);
            break;
        case IPPROTO_ICMP:
            if (preferences.transport_selected) {
                set_subwindow_line(i, "- Internet Control Message Protocol (ICMP)", true, ICMP_HDR);
            } else {
                set_subwindow_line(i, "+ Internet Control Message Protocol (ICMP)", false, ICMP_HDR);
            }
            break;
        case IPPROTO_IGMP:
            if (preferences.transport_selected) {
                set_subwindow_line(i, "- Internet Group Management Protocol (IGMP)", true, ICMP_HDR);
            } else {
                set_subwindow_line(i, "+ Internet Group Management Protocol (IGMP)", false, ICMP_HDR);
            }
            break;
        }
    } else if (p->eth.ethertype < ETH_P_802_3_MIN) {
        if (preferences.link_llc_selected) {
            set_subwindow_line(i, "- Logical Link Control (LLC)", true, LLC_HDR);
            i += ETH_WINSIZE;
        } else {
            set_subwindow_line(i, "+ Logical Link Control (LLC)", false, LLC_HDR);
            i++;
        }
        if (preferences.link_stp_selected) {
            set_subwindow_line(i, "- Spanning Tree Protocol (STP)", true, STP_HDR);
            i += ETH_WINSIZE;
        } else {
            set_subwindow_line(i, "+ Spanning Tree Protocol (STP)", false, STP_HDR);
            i += 2;
        }
    }
}

void create_app_sublines(struct packet *p, int i)
{
    switch (p->eth.ip->udp.data.utype) {
    case DNS:
        if (preferences.application_selected) {
            set_subwindow_line(i, "- Domain Name System (DNS)", true, APP_HDR);
        } else {
            set_subwindow_line(i, "+ Domain Name System (DNS)", false, APP_HDR);
        }
    break;
    case NBNS:
        if (preferences.application_selected) {
            set_subwindow_line(i, "- NetBIOS Name Service (NBNS)", true, APP_HDR);
        } else {
            set_subwindow_line(i, "+ NetBIOS Name Service (NBNS)", false, APP_HDR);
        }
        break;
    case HTTP:
        if (preferences.application_selected) {
            set_subwindow_line(i, "- Hypertext Transfer Protocol (HTTP)", true, APP_HDR);
        } else {
            set_subwindow_line(i, "+ Hypertext Transfer Protocol (HTTP)", false, APP_HDR);
        }
        break;
    case SSDP:
        if (preferences.application_selected) {
            set_subwindow_line(i, "- Simple Service Discovery Protocol (SSDP)", true, APP_HDR);
        } else {
            set_subwindow_line(i, "+ Simple Service Discovery Protocol (SSDP)", false, APP_HDR);
        }
        break;
    default:
        if (preferences.application_selected) {
            set_subwindow_line(i, "- Data", true, APP_HDR);
        } else {
            set_subwindow_line(i, "+ Data", false, APP_HDR);
        }
        break;
    }
}

void set_subwindow_line(int i, char *text, bool selected, enum header_type type)
{
    subwindow.line[i].text = text;
    subwindow.line[i].selected = selected;
    subwindow.line[i].selectable = true;
    subwindow.line[i].type = type;
}

/*
 * Print more information about a packet when selected. This will print more
 * details about the specific protocol headers and payload.
 */
void print_selected_packet()
{
    int screen_line;
    struct packet *p;
    static int prev_selection = -1;

    if (prev_selection >= 0) {
        if (subwindow.win) {
            bool inside_subwin;

            inside_subwin = update_subwin_selection(prev_selection);
            if (inside_subwin) {
                p = vector_get_data(vector, prev_selection);
                print_protocol_information(p, prev_selection);
                return;
            }
        }
    }
    screen_line = selection_line - top;
    line[screen_line].selected = !line[screen_line].selected;
    if (line[screen_line].selected) {
        p = vector_get_data(vector, selection_line);
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
 */
bool update_subwin_selection(int lineno)
{
    int screen_line;

    screen_line = selection_line - top;
    if (screen_line >= subwindow.top &&
        screen_line <= subwindow.top + subwindow.num_lines) {
        int subline;

        subline = screen_line - subwindow.top;
        if (subwindow.line[subline].selectable) {
            subwindow.line[subline].selected = !subwindow.line[subline].selected;
            switch (subwindow.line[subline].type) {
            case ETHERNET_HDR:
                preferences.link_selected = subwindow.line[subline].selected;
                break;
            case ARP_HDR:
                preferences.link_arp_selected = subwindow.line[subline].selected;
                break;
            case LLC_HDR:
                preferences.link_llc_selected = subwindow.line[subline].selected;
                break;
            case STP_HDR:
                preferences.link_stp_selected = subwindow.line[subline].selected;
                break;
            case IP_HDR:
                preferences.network_selected = subwindow.line[subline].selected;
                break;
            case UDP_HDR:
            case TCP_HDR:
            case IGMP_HDR:
            case ICMP_HDR:
                preferences.transport_selected = subwindow.line[subline].selected;
                break;
            case APP_HDR:
                preferences.application_selected = subwindow.line[subline].selected;
                break;
            default:
                break;
            }
        }
        return true;
    }
    return false;
}

/* Calculate size of subwindow */
int calculate_subwin_size(struct packet *p, int screen_line)
{
    int size = 0;

    if (preferences.link_selected) {
        size += ETH_WINSIZE;
    } else {
        size++;
    }
    switch (p->eth.ethertype) {
    case ETH_P_ARP:
        if (preferences.link_arp_selected) {
            size += ARP_WINSIZE;
        } else {
            size += 2;
        }
        break;
    case ETH_P_IP:
        if (preferences.network_selected) {
            size += IP_WINSIZE;
        } else {
            size++;
        }
        switch (p->eth.ip->protocol) {
        case IPPROTO_UDP:
            if (preferences.transport_selected) {
                size += UDP_WINSIZE;
            } else {
                size++;
            }
            size += calculate_applayer_size(&p->eth.ip->udp.data, screen_line);
            break;
        case IPPROTO_TCP:
            if (preferences.transport_selected) {
                size += TCP_WINSIZE;
            } else {
                size++;
            }
            size += calculate_applayer_size(&p->eth.ip->tcp.data, screen_line);
            break;
        case IPPROTO_ICMP:
            if (preferences.transport_selected) {
                size += 7;
            } else {
                size += 2;
            }
            break;
        case IPPROTO_IGMP:
            if (preferences.transport_selected) {
                size += IGMP_WINSIZE;
            } else {
                size += 2;
            }
            break;
        }
        break;
    default:
        if (p->eth.ethertype < ETH_P_802_3_MIN) {
            if (preferences.link_llc_selected) {
                size += ETH_WINSIZE;
            } else {
                size++;
            }
            if (p->eth.llc->dsap == 0x42 && p->eth.llc->ssap == 0x42) {
                if (preferences.link_stp_selected) {
                    size += 14;
                } else {
                    size += 2;
                }
            }
        }
        break;
    }
    return size;
}

int calculate_applayer_size(struct application_info *info, int screen_line)
{
    int size = 0;

    switch (info->utype) {
    case DNS:
        if (preferences.application_selected) {
            int records = 0;

            /* number of resource records */
            for (int i = 1; i < 4; i++) {
                records += info->dns->section_count[i];
            }
            size += (info->dns->section_count[NSCOUNT] ? 19 + records : 11 + records);
        } else {
            size += 2;
        }
        break;
    case NBNS:
        if (preferences.application_selected) {
            int records = 0;

            /* number of resource records */
            for (int i = 1; i < 4; i++) {
                records += info->nbns->section_count[i];
            }
            size += (records ? 11 + records : 10);
        } else {
            size += 2;
        }
        break;
    case HTTP:
        break;
    case SSDP:
        if (preferences.application_selected) {
            size += list_size(info->ssdp) + 2;
        } else {
            size += 2;
        }
        break;
    default:
        if (preferences.application_selected) {
            size += info->payload_len / 16 + 3;
        } else {
            size += 2;
        }
        break;
    }
    return size;
}

void print_protocol_information(struct packet *p, int lineno)
{
    int size;

    size = calculate_subwin_size(p, lineno);

    /* Delete old subwindow. TODO: Possible to just resize? */
    if (subwindow.win) {
        delete_subwindow();
    }

    /* print information in subwindow */
    create_subwindow(size, lineno);
    create_sublines(p, size);
    for (int i = 0; i < subwindow.num_lines; i++) {
        if (subwindow.line[i].text) {
            mvwprintw(subwindow.win, i, 2, subwindow.line[i].text);
        }
        if (subwindow.line[i].selected) {
            switch (subwindow.line[i].type) {
            case ETHERNET_HDR:
                print_ethernet_verbose(subwindow.win, p, i + 1);
                break;
            case ARP_HDR:
                print_arp_verbose(subwindow.win, p, i + 1);
                break;
            case LLC_HDR:
                print_llc_verbose(subwindow.win, p, i + 1);
                break;
            case STP_HDR:
                print_stp_verbose(subwindow.win, p, i + 1);
                break;
            case IP_HDR:
                print_ip_verbose(subwindow.win, p->eth.ip, i + 1);
                break;
            case TCP_HDR:
                print_tcp_verbose(subwindow.win, p->eth.ip, i + 1);
                break;
            case UDP_HDR:
                print_udp_verbose(subwindow.win, p->eth.ip, i + 1);
                break;
            case ICMP_HDR:
                print_icmp_verbose(subwindow.win, p->eth.ip, i + 1);
                break;
            case IGMP_HDR:
                print_igmp_verbose(subwindow.win, p->eth.ip, i + 1);
                break;
            case APP_HDR:
                if (p->eth.ip->protocol == IPPROTO_UDP) {
                    print_app_protocol(&p->eth.ip->udp.data, i + 1);
                } else {
                    print_app_protocol(&p->eth.ip->tcp.data, i + 1);
                }
                break;
            default:
                break;
            }
        }
    }
    mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 1, NULL);
    touchwin(wmain);
    wrefresh(subwindow.win);
}

void print_app_protocol(struct application_info *info, int y)
{
    switch (info->utype) {
    case DNS:
        print_dns_verbose(subwindow.win, info->dns, y, getmaxx(wmain));
        break;
    case NBNS:
        print_nbns_verbose(subwindow.win, info->nbns, y, getmaxx(wmain));
        break;
    case SSDP:
        print_ssdp_verbose(subwindow.win, info->ssdp, y);
        break;
    case HTTP:
        print_http_verbose(subwindow.win, info->http, y);
        break;
    default:
        print_payload(subwindow.win, info->payload, info->payload_len, y);
        break;
    }
}
