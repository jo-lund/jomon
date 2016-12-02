#include <string.h>
#include <signal.h>
#include <linux/igmp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
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

static bool selected[NUM_LAYERS - 1];

static struct line_info {
    int line_number;
    bool selected;
} main_line;

static struct subwin_info {
    WINDOW *win;
    unsigned int top; /* index to the first line in the subwindow relative to the
                         main window */
    unsigned int num_lines;
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
static void print_header(context *c);
static void print_selected_packet();
static void print_protocol_information(struct packet *p, int lineno);

/* Handles subwindow layout */
static void create_subwindow(int num_lines, int lineno);
static void delete_subwindow();
static bool update_subwin_selection();
static void add_elements(struct packet *p);
static void add_transport_elements(struct packet *p);
static void add_app_elements(struct application_info *info, uint8_t protocol);

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

void create_layout(context *c)
{
    int mx, my;

    getmaxyx(stdscr, my, mx);
    wheader = newwin(HEADER_HEIGHT, mx, 0, 0);
    wmain = newwin(my - HEADER_HEIGHT - STATUS_HEIGHT, mx, HEADER_HEIGHT, 0);
    wstatus = newwin(STATUS_HEIGHT, mx, my - STATUS_HEIGHT, 0);
    nodelay(wmain, TRUE); /* input functions must be non-blocking */
    keypad(wmain, TRUE);
    print_header(c);
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
                      GET_ATTR(lw, subline - 1), 1, NULL);
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
            mvwchgat(wmain, screen_line + 1, 0, -1, GET_ATTR(lw, subline + 1), 1, NULL);
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
        if (subwindow.win) {
            delete_subwindow();
            main_line.selected = false;
        }
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

void print_header(context *c)
{
    int y = 0;
    char addr[INET_ADDRSTRLEN];

    if (c->filename) {
        mvwprintw(wheader, y, 0, "Filename: %s", c->filename);
    } else {
        mvwprintw(wheader, y, 0, "Listening on device: %s", c->device);
    }
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
    set_interactive(true, -1, -1);
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

        inside_subwin = update_subwin_selection();
        if (inside_subwin) {
            p = vector_get_data(vector, prev_selection);
            print_protocol_information(p, prev_selection);
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
        add_elements(p);
        print_protocol_information(p, selection_line);
    } else {
        delete_subwindow();
    }
    prev_selection = selection_line + scrollvy;
}

void add_elements(struct packet *p)
{
    list_view_item *header;

    if (lw) {
        free_list_view(lw);
    }
    lw = create_list_view();

    /* inspect packet and add packet headers as elements to the list view */
    if (p->eth.ethertype < ETH_P_802_3_MIN) {
        header = ADD_HEADER(lw, "Ethernet 802.3", selected[ETHERNET_LAYER], ETHERNET_LAYER);
    } else {
        header = ADD_HEADER(lw, "Ethernet II", selected[ETHERNET_LAYER], ETHERNET_LAYER);
    }
    add_ethernet_information(lw, header, p);
    if (p->eth.ethertype == ETH_P_ARP) {
        header = ADD_HEADER(lw, "Address Resolution Protocol (ARP)", selected[ARP], ARP);
        add_arp_information(lw, header, p);
    } else if (p->eth.ethertype == ETH_P_IP) {
        header = ADD_HEADER(lw, "Internet Protocol (IPv4)", selected[IP], IP);
        add_ipv4_information(lw, header, p->eth.ip);
        add_transport_elements(p);
    } else if (p->eth.ethertype == ETH_P_IPV6) {
        header = ADD_HEADER(lw, "Internet Protocol (IPv6)", selected[IP], IP);
        add_ipv6_information(lw, header, p->eth.ipv6);
        add_transport_elements(p);
    } else if (p->eth.ethertype < ETH_P_802_3_MIN) {
        header = ADD_HEADER(lw, "Logical Link Control (LLC)", selected[LLC], LLC);
        add_llc_information(lw, header, p);
        switch (get_eth802_type(p->eth.llc)) {
        case ETH_802_STP:
            header = ADD_HEADER(lw, "Spanning Tree Protocol (STP)", selected[STP], STP);
            add_stp_information(lw, header, p);
            break;
        case ETH_802_SNAP:
            header = ADD_HEADER(lw, "Subnetwork Access Protocol (SNAP)", selected[SNAP], SNAP);
            add_snap_information(lw, header, p);
            break;
        default:
            header = ADD_HEADER(lw, "Data", selected[APPLICATION], APPLICATION);
            add_payload(lw, header, p->eth.llc->payload, p->eth.llc->payload_len);
        }
    } else if (p->eth.payload_len) {
        header = ADD_HEADER(lw, "Data", selected[APPLICATION], APPLICATION);
        add_payload(lw, header, p->eth.payload, p->eth.payload_len);
    }
}

void add_transport_elements(struct packet *p)
{
    list_view_item *header;
    uint8_t protocol = (p->eth.ethertype == ETH_P_IP) ? p->eth.ip->protocol : p->eth.ipv6->next_header; 

    switch (protocol) {
    case IPPROTO_TCP:
        header = ADD_HEADER(lw, "Transmission Control Protocol (TCP)", selected[TRANSPORT], TRANSPORT);
        if (p->eth.ethertype == ETH_P_IP) {
            add_tcp_information(lw, header, &p->eth.ip->tcp, selected[SUBLAYER]);
            add_app_elements(&p->eth.ip->tcp.data, protocol);
        } else {
            add_tcp_information(lw, header, &p->eth.ipv6->tcp, selected[SUBLAYER]);
            add_app_elements(&p->eth.ipv6->tcp.data, protocol);
        }
        break;
    case IPPROTO_UDP:
        header = ADD_HEADER(lw, "User Datagram Protocol (UDP)", selected[TRANSPORT], TRANSPORT);
        if (p->eth.ethertype == ETH_P_IP) {
            add_udp_information(lw, header, &p->eth.ip->udp);
            add_app_elements(&p->eth.ip->udp.data, protocol);
        } else {
            add_udp_information(lw, header, &p->eth.ipv6->udp);
            add_app_elements(&p->eth.ipv6->udp.data, protocol);
        }
        break;
    case IPPROTO_ICMP:
        if (p->eth.ethertype == ETH_P_IP) {
            header = ADD_HEADER(lw, "Internet Control Message Protocol (ICMP)", selected[ICMP], ICMP);
            add_icmp_information(lw, header, &p->eth.ip->icmp);
        }
        break;
    case IPPROTO_IGMP:
        header = ADD_HEADER(lw, "Internet Group Management Protocol (IGMP)", selected[IGMP], IGMP);
        if (p->eth.ethertype == ETH_P_IP) {
            add_igmp_information(lw, header, &p->eth.ip->igmp);
        } else {
            add_igmp_information(lw, header, &p->eth.ipv6->igmp);
        }
        break;
    default:
        /* unknown transport layer payload */
        if (p->eth.ethertype == ETH_P_IP && p->eth.ip->payload_len) {
            header = ADD_HEADER(lw, "Data", selected[APPLICATION], APPLICATION);
            add_payload(lw, header, p->eth.ip->payload, p->eth.ip->payload_len);
        }
    }
}

void add_app_elements(struct application_info *info, uint8_t protocol)
{
    list_view_item *header;

    switch (info->utype) {
    case DNS:
    case MDNS:
        header = ADD_HEADER(lw, "Domain Name System (DNS)", selected[APPLICATION], APPLICATION);
        add_dns_information(lw, header, info->dns, selected[SUBLAYER]);
        break;
    case NBNS:
        header = ADD_HEADER(lw, "NetBIOS Name Service (NBNS)", selected[APPLICATION], APPLICATION);
        add_nbns_information(lw, header, info->nbns);
        break;
    case HTTP:
        header = ADD_HEADER(lw, "Hypertext Transfer Protocol (HTTP)", selected[APPLICATION], APPLICATION);
        add_http_information(lw, header, info->http);
        break;
    case SSDP:
        header = ADD_HEADER(lw, "Simple Service Discovery Protocol (SSDP)", selected[APPLICATION], APPLICATION);
        add_ssdp_information(lw, header, info->ssdp);
        break;
    default:
        if ((protocol == IPPROTO_TCP && info->payload_len > 0) || protocol == IPPROTO_UDP) {
            header = ADD_HEADER(lw, "Data", selected[APPLICATION], APPLICATION);
            add_payload(lw, header, info->payload, info->payload_len);
        }
        break;
    }
}

void print_protocol_information(struct packet *p, int lineno)
{
    /* Delete old subwindow. TODO: Don't use a subwindow for this */
    if (subwindow.win) {
        delete_subwindow();
    }
    
    /* print information in subwindow */
    create_subwindow(lw->size + 1, lineno);
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

bool update_subwin_selection()
{
    int screen_line;

    screen_line = selection_line - top;
    if (screen_line >= subwindow.top &&
        screen_line < subwindow.top + subwindow.num_lines) {
        int subline;
        int32_t data;

        subline = screen_line - subwindow.top;
        data = GET_DATA(lw, subline);
        SET_EXPANDED(lw, subline, !GET_EXPANDED(lw, subline));
        if (data >= 0 && data < NUM_LAYERS) {
            selected[data] = GET_EXPANDED(lw, subline);
        }
        return true;
    }
    return false;
}
