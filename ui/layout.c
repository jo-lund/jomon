#include <string.h>
#include <signal.h>
#include <linux/igmp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include "../misc.h"
#include "layout.h"
#include "protocols.h"
#include "../list.h"
#include "../error.h"
#include "../util.h"
#include "../vector.h"
#include "../decoder/decoder.h"
#include "list_view.h"

#define HEADER_HEIGHT 4
#define STATUS_HEIGHT 1
#define KEY_ESC 27

static struct preferences {
    bool link_selected;
    bool network_selected;
    bool transport_selected;
    bool application_selected;
} preferences;

enum layer {
    LINK,
    NETWORK,
    TRANSPORT,
    APPLICATION
};

static struct line_info {
    int line_number;
    bool selected;
} main_line;

static struct subwin_info {
    WINDOW *win;
    unsigned int top; /* index to the first line in the subwindow relative to the
                         main window */
    unsigned int num_lines;
    struct subline_info {
        bool selectable;
        bool selected;
        char *text;
        uint32_t attr;
    } *line;
} subwindow;

extern vector_t *vector;
bool numeric = true;
static WINDOW *wheader;
static WINDOW *wmain;
static WINDOW *wstatus;
static int outy = 0;
static bool interactive = false;
static int selection_line = 0; /* index to the selection bar */
static bool capturing = true;
static list_view *lw;

/*
 * Index to top of main window. The main screen will be between top + maximum 
 * number of lines of the main window, i.e. getmaxy(wmain).
 */
static int top = 0;

/* the number of lines to be scrolled in order to print packet information */
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
static void print_selected_packet();
static void print_protocol_information(struct packet *p, int lineno);
static int print_app_protocol(struct application_info *info, int y);

/* Handles subwindow layout */
static void create_subwindow(int num_lines, int lineno);
static void delete_subwindow();
static bool update_subwin_selection();
static int calculate_subwin_size(struct packet *p);
static int calculate_applayer_size(struct application_info *info);
static int calculate_tcp_options_size(struct tcp *tcp);
static int calculate_dns_size(struct dns_info *dns);
static void create_app_sublines(struct packet *p, int i);

static void create_elements(struct packet *p);
static void create_app_elements(struct packet *p);
static void print_protocol_information2(struct packet *p, int lineno);
static bool update_subwin_selection2();

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
        if (subwindow.win) {
            subwindow.top++;
            main_line.line_number++;
        }
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
         if (subwindow.win && screen_line >= subwindow.top &&
             screen_line < subwindow.top + subwindow.num_lines) {
             int subline = screen_line - subwindow.top;

             mvwchgat(wmain, screen_line, 0, -1, GET_ATTR(lw, subline), 0, NULL);
             mvwchgat(wmain, screen_line - 1, 0, -1, subline == 0 ? A_NORMAL :
                      GET_ATTR(lw, subline), 1, NULL);
         } else {
             mvwchgat(wmain, screen_line, 0, -1, A_NORMAL, 0, NULL);
             mvwchgat(wmain, screen_line - 1, 0, -1, A_NORMAL, 1, NULL);
         }
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
        if (subwindow.win) {
            subwindow.top--;
            main_line.line_number--;
        }
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
        if (subwindow.win && screen_line + 1 >= subwindow.top &&
            screen_line + 1 < subwindow.top + subwindow.num_lines) {
            int subline = screen_line - subwindow.top;

            mvwchgat(wmain, screen_line, 0, -1, subline == -1 ? A_NORMAL :
                     GET_ATTR(lw, subline), 0, NULL);
            mvwchgat(wmain, screen_line + 1, 0, -1, GET_ATTR(lw, subline), 1, NULL);
        } else {
            mvwchgat(wmain, screen_line, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain, screen_line + 1, 0, -1, A_NORMAL, 1, NULL);
        }
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
                if (subwindow.win) {
                    subwindow.top -= scroll;
                    main_line.line_number -= scroll;
                }
                if (selection_line >= vector_size(vector)) {
                    selection_line = vector_size(vector) - 1;
                }
                print_lines(bottom + 1, vector_size(vector), vector_size(vector) - scroll - top, cols);
            } else {
                top += lines;
                if (subwindow.win) {
                    subwindow.top -= lines;
                    main_line.line_number -= lines;
                }
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
                if (subwindow.win) {
                    subwindow.top -= lines;
                    main_line.line_number -= lines;
                }
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

/*
 * Print more information about a packet when selected. This will print more
 * details about the specific protocol headers and payload.
 */
void print_selected_packet()
{
    int screen_line;
    struct packet *p;
    static int prev_selection = -1;

    if (prev_selection >= 0 && subwindow.win) {
        bool inside_subwin;

        inside_subwin = update_subwin_selection2();
        if (inside_subwin) {
            p = vector_get_data(vector, prev_selection);
            print_protocol_information2(p, prev_selection);
            return;
        }
    }
    screen_line = selection_line + scrollvy - top;
    if (screen_line == main_line.line_number) {
        main_line.selected = !main_line.selected;
    } else {
        main_line.selected = true;

        /* the index to the selected line needs to be adjusted in case of an
           open subwindow */
        if (subwindow.win && screen_line > subwindow.top) {
            main_line.line_number = screen_line - subwindow.num_lines;
            selection_line -= subwindow.num_lines;
        } else {
            main_line.line_number = screen_line;
        }
    }
    if (main_line.selected) {
        p = vector_get_data(vector, selection_line);
        print_protocol_information2(p, selection_line);
    } else {
        delete_subwindow();
    }
    prev_selection = selection_line + scrollvy;
}

void create_elements(struct packet *p)
{
    lw = create_list_view();

    /* inspect packet and add packet headers as elements to the list view */
    if (p->eth.ethertype < ETH_P_802_3_MIN) {
        ADD_HEADER(lw, "Ethernet 802.3", preferences.link_selected, LINK);
    } else {
        ADD_HEADER(lw, "Ethernet II", preferences.link_selected, LINK);
    }
    if (preferences.link_selected) {
        print_ethernet_information(lw, p);
    }

    // if expanded add each line as a list_view_widget containing just text. Do that for every type of header.
    if (p->eth.ethertype == ETH_P_ARP) {
        ADD_HEADER(lw, "Address Resolution Protocol (ARP)", preferences.network_selected, NETWORK);
        if (preferences.network_selected) {
            print_arp_information(lw, p);
        }
    } else if (p->eth.ethertype == ETH_P_IP) {
        ADD_HEADER(lw, "Internet Protocol (IP)", preferences.network_selected, NETWORK);
        if (preferences.network_selected) {
            print_ip_information(lw, p->eth.ip);
        }
        switch (p->eth.ip->protocol) {
        case IPPROTO_TCP:
        {
            list_view_widget *w = ADD_HEADER(lw, "Transmission Control Protocol (TCP)", preferences.transport_selected, TRANSPORT);

            if (preferences.transport_selected) {
                print_tcp_information(lw, p->eth.ip);
            }
            if (p->eth.ip->tcp.options) {
                ADD_SUB_HEADER(lw, w, "Options", false); // TODO: Fix sublayer preferences
            }
            create_app_elements(p);
            break;
        }
        case IPPROTO_UDP:
            ADD_HEADER(lw, "User Datagram Protocol (UDP)", preferences.transport_selected, TRANSPORT);
            if (preferences.transport_selected) {
                print_udp_information(lw, p->eth.ip);
            }
            create_app_elements(p);
            break;
        case IPPROTO_ICMP:
            ADD_HEADER(lw, "Internet Control Message Protocol (ICMP)", preferences.transport_selected, TRANSPORT);
            if (preferences.transport_selected) {
                print_icmp_information(lw, p->eth.ip);
            }
            break;
        case IPPROTO_IGMP:
            ADD_HEADER(lw, "Internet Group Management Protocol (IGMP)", preferences.transport_selected, TRANSPORT);
            if (preferences.transport_selected) {
                print_igmp_information(lw, p->eth.ip);
            }
            break;
        default:
            /* unknown transport layer payload */
            if (p->eth.ip->payload_len) {
                ADD_HEADER(lw, "Data", preferences.transport_selected, TRANSPORT);
                if (preferences.transport_selected) {
                    print_payload(lw, p->eth.ip->payload, p->eth.ip->payload_len);
                }
            }
        }
    } else if (p->eth.ethertype < ETH_P_802_3_MIN) {
        ADD_HEADER(lw, "Logical Link Control (LLC)", preferences.network_selected, NETWORK);
        if (preferences.network_selected) {
            print_llc_information(lw, p);
        }
        switch (get_eth802_type(p->eth.llc)) {
        case ETH_802_STP:
            ADD_HEADER(lw, "Spanning Tree Protocol (STP)", preferences.transport_selected, TRANSPORT);
            if (preferences.transport_selected) {
                print_stp_information(lw, p);
            }
            break;
        case ETH_802_SNAP:
            ADD_HEADER(lw, "Subnetwork Access Protocol (SNAP)", preferences.transport_selected, TRANSPORT);
            if (preferences.transport_selected) {
                print_stp_information(lw, p);
            }
            break;
        default:
            ADD_HEADER(lw, "Data", preferences.application_selected, APPLICATION);
            if (preferences.application_selected) {
                print_payload(lw, p->eth.payload, p->eth.payload_len);
            }
        }
    } else if (p->eth.payload_len) {
        ADD_HEADER(lw, "Data", preferences.application_selected, APPLICATION);
    }
}

void create_app_elements(struct packet *p)
{
    switch (p->eth.ip->udp.data.utype) {
    case DNS:
    case MDNS:
        ADD_HEADER(lw, "Domain Name System (DNS)", preferences.application_selected, APPLICATION);
        // TODO: Traverse resource records and add them as sub elements
        break;
    case NBNS:
        ADD_HEADER(lw, "NetBIOS Name Service (NBNS)", preferences.application_selected, APPLICATION);
        break;
    case HTTP:
        ADD_HEADER(lw, "Hypertext Transfer Protocol (HTTP)", preferences.application_selected, APPLICATION);
        break;
    case SSDP:
        ADD_HEADER(lw, "Simple Service Discovery Protocol (SSDP)", preferences.application_selected, APPLICATION);
        break;
    default:
        if ((p->eth.ip->protocol == IPPROTO_TCP && TCP_PAYLOAD_LEN(p) > 0) ||
            p->eth.ip->protocol == IPPROTO_UDP) {
            ADD_HEADER(lw, "Data", preferences.application_selected, APPLICATION);
        }
        break;
    }
}

void print_protocol_information2(struct packet *p, int lineno)
{
    int size = 40;

    /* Delete old subwindow. TODO: Possible to just resize? */
    if (subwindow.win) {
        delete_subwindow();
        free_list_view(lw);
    }
    create_elements(p);
    
    /* print information in subwindow */
    create_subwindow(lw->num_elements + 1, lineno);
    RENDER(lw, subwindow.win);

    int subline = selection_line - top - subwindow.top;
    if (subline >= 0) {
        mvwchgat(wmain, selection_line - top, 0, -1, GET_ATTR(lw, subline), 1, NULL);
    } else {
        mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 1, NULL);
    }
    touchwin(wmain);
    wrefresh(subwindow.win);
}

int print_app_protocol(struct application_info *info, int y)
{
    switch (info->utype) {
    case DNS:
    case MDNS:
        return print_dns_verbose(subwindow.win, info->dns, y, getmaxx(wmain));
    case NBNS:
        return print_nbns_verbose(subwindow.win, info->nbns, y, getmaxx(wmain));
    case SSDP:
        print_ssdp_information(lw, info->ssdp);
        break;
    case HTTP:
        print_http_information(lw, info->http);
        break;
    default:
        print_payload(lw, info->payload, info->payload_len);
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
    if (num_lines >= my) num_lines = my - 1;

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
    subwindow.line = calloc(num_lines, sizeof(struct subline_info));
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

/*
 * Checks if selection_line is inside the subwindow, and if that's the case, updates the
 * selection status of the selectable subwindow line.
 *
 * Returns true if it's inside the subwindow, else false.
 */

bool update_subwin_selection2()
{
    int screen_line;

    screen_line = selection_line - top;
    if (screen_line >= subwindow.top &&
        screen_line < subwindow.top + subwindow.num_lines) {
        int subline;

        subline = screen_line - subwindow.top;
        SET_EXPANDED(lw, subline, !GET_EXPANDED(lw, subline));
        switch (GET_DATA(lw, subline)) {
        case LINK:
            preferences.link_selected = GET_EXPANDED(lw, subline);
            break;
        case NETWORK:
            preferences.network_selected = GET_EXPANDED(lw, subline);
            break;
        case TRANSPORT:
            preferences.transport_selected = GET_EXPANDED(lw, subline);
            break;
        case APPLICATION:
            preferences.application_selected = GET_EXPANDED(lw, subline);
            break;
        default:
            break;
        }
        return true;
    }
    return false;
}

