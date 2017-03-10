#include <string.h>
#include <signal.h>
#include <linux/igmp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>
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

typedef struct {
    struct line_info {
        int line_number;
        bool selected;
    } main_line;

    struct subwin_info {
        WINDOW *win;
        unsigned int top; /* index to the first line in the subwindow relative to the
                             main window */
        unsigned int num_lines;
    } subwindow;

    WINDOW *win;
    int outy;
    int selection_line; /* index to the selection bar */

    /*
     * Index to top of main window. The main screen will be between top + maximum
     * number of lines of the main window, i.e. getmaxy(main_window->win).
     */
    int top;

    /* the number of lines to be scrolled in order to print packet information */
    int scrolly;

    int scrollx;
} main_window;

extern vector_t *packets;
bool numeric = true;
static bool selected[NUM_LAYERS];
static WINDOW *wheader;
static WINDOW *wstatus;
static main_window *wmain;
static list_view *lw;
static bool capturing = true;
static bool interactive = false;
static bool input_mode = false;

static main_window *create_main_window(int nlines, int ncols, int beg_y, int beg_x);
static void free_main_window(main_window *mw);
static void set_interactive(bool interactive_mode, int num_lines);
static bool check_line();
static void handle_keydown(int num_lines);
static void handle_keyup(int num_lines);
static void scroll_page(int num_lines);
static void scroll_window();
static int print_lines(int from, int to, int y);
static void print(char *buf);
static void print_header(context *c);
static void print_status();
static void print_selected_packet();
static void print_protocol_information(struct packet *p, int lineno);
static void goto_line(int c);

/* Handles subwindow layout */
static void create_subwindow(int num_lines, int lineno);
static void delete_subwindow();
static bool update_subwin_selection();
static void add_elements(struct packet *p);
static void add_transport_elements(struct packet *p);
static void add_app_elements(struct application_info *info, uint16_t len);

void init_ncurses()
{
    initscr(); /* initialize curses mode */
    cbreak(); /* disable line buffering */
    noecho();
    curs_set(0); /* make the cursor invisible */
    use_default_colors();
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_CYAN);
    init_pair(2, COLOR_BLACK, COLOR_CYAN);
    set_escdelay(25); /* set escdelay to 25 ms */
}

void end_ncurses()
{
    free_main_window(wmain);
    endwin(); /* end curses mode */
}

void create_layout(context *c)
{
    int mx, my;

    getmaxyx(stdscr, my, mx);
    wheader = newwin(HEADER_HEIGHT, mx, 0, 0);
    wstatus = newwin(STATUS_HEIGHT, mx, my - STATUS_HEIGHT, 0);
    wmain = create_main_window(my - HEADER_HEIGHT - STATUS_HEIGHT, mx, HEADER_HEIGHT, 0);
    nodelay(wmain->win, TRUE); /* input functions must be non-blocking */
    keypad(wmain->win, TRUE);
    print_header(c);
    print_status();
    scrollok(wmain->win, TRUE); /* enable scrolling */
}

main_window *create_main_window(int nlines, int ncols, int beg_y, int beg_x)
{
    main_window *wm = malloc(sizeof(main_window));

    wm->outy = 0;
    wm->selection_line = 0;
    wm->top = 0;
    wm->scrolly = 0;
    wm->scrollx = 0;
    wm->win = newwin(nlines, ncols, beg_y, beg_x);
    return wm;
}

void free_main_window(main_window *mw)
{
    if (mw->subwindow.win) {
        delwin(mw->subwindow.win);
    }
    delwin(mw->win);
    free(mw);
}

/* scroll the window if necessary */
void scroll_window()
{
    int my;

    my = getmaxy(wmain->win);
    if (wmain->outy >= my) {
        wmain->outy = my - 1;
        scroll(wmain->win);
        wmain->top++;
    }
}

void get_input()
{
    int c = 0;
    int my;

    my = getmaxy(wmain->win);
    c = wgetch(wmain->win);
    switch (c) {
    case 'i':
        set_interactive(!interactive, my);
        break;
    case 'q':
        finish();
        break;
    case 'n':
        numeric = !numeric;
        break;
    case KEY_UP:
        handle_keyup(my);
        break;
    case KEY_DOWN:
        handle_keydown(my);
        break;
    case KEY_ENTER:
    case '\n':
        if (input_mode) {
            goto_line(c);
        } else if (interactive) {
            print_selected_packet();
        }
        break;
    case KEY_ESC:
        if (input_mode) {
            curs_set(0);
            werase(wstatus);
            print_status();
            input_mode = false;
        } else if (interactive) {
            set_interactive(false, my);
        }
        break;
    case ' ':
    case KEY_NPAGE:
        scroll_page(my);
        break;
    case 'b':
    case KEY_PPAGE:
        scroll_page(-my);
        break;
    case 'g':
        input_mode = !input_mode;
        if (input_mode) {
            werase(wstatus);
            mvwprintw(wstatus, 0, 0, "Go to line: ");
            curs_set(1);
        } else {
            curs_set(0);
            werase(wstatus);
            print_status();
        }
        wrefresh(wstatus);
        break;
    default:
        if (input_mode) {
            goto_line(c);
        }
        break;
    }
}

void goto_line(int c)
{
    static uint32_t num = 0;

    if (isdigit(c)) {
        waddch(wstatus, c);
        num = num * 10 + c - '0';
    } else if (c == KEY_BACKSPACE) {
        int x, y;

        getyx(wstatus, y, x);
        if (x >= 13) {
            mvwdelch(wstatus, y, x - 1);
            num /= 10;
        }
    } else if (num && (c == '\n' || c == KEY_ENTER)) {
        int my;

        my = getmaxy(wmain->win);
        if (num >= wmain->top && num < wmain->top + my) {
            mvwchgat(wmain->win, wmain->selection_line, 0, -1, A_NORMAL, 0, NULL);
            wmain->selection_line = num - 1;
            mvwchgat(wmain->win, wmain->selection_line, 0, -1, A_NORMAL, 1, NULL);
            wrefresh(wmain->win);
            curs_set(0);
            werase(wstatus);
            input_mode = false;
            num = 0;
            print_status();
        } else if (num < vector_size(packets)) {
            werase(wmain->win);
            mvwchgat(wmain->win, wmain->selection_line, 0, -1, A_NORMAL, 0, NULL);
            if (num + my - 1 > vector_size(packets)) {
                print_lines(vector_size(packets) - my, vector_size(packets), 0);
                wmain->top = vector_size(packets) - my;
                wmain->selection_line = num - 1;
                mvwchgat(wmain->win, num - 1 - wmain->top, 0, -1, A_NORMAL, 1, NULL);
            } else {
                print_lines(num - 1, num + my - 1, 0);
                wmain->selection_line = wmain->top = num - 1;
                mvwchgat(wmain->win, 0, 0, -1, A_NORMAL, 1, NULL);
            }
            wrefresh(wmain->win);
            curs_set(0);
            werase(wstatus);
            input_mode = false;
            num = 0;
            print_status();
        }
    }
    wrefresh(wstatus);
}

/*
 * Checks if there still are lines to highlight when moving the selection bar
 * down. Returns true if that's the case.
 */
bool check_line()
{
    int num_lines = 0;

    if (wmain->subwindow.win) {
        num_lines += wmain->subwindow.num_lines - 1;
    }
    if (wmain->selection_line < vector_size(packets) + num_lines - 1) {
        return true;
    }
    return false;
}

void handle_keyup(int num_lines)
{
    if (!interactive) {
        set_interactive(true, num_lines);
    }

    /* scroll screen if the selection bar is at the top */
    if (wmain->top && wmain->selection_line == wmain->top) {
        struct packet *p = vector_get_data(packets, --wmain->selection_line);

        wmain->top--;
        if (wmain->subwindow.win) {
            wmain->subwindow.top++;
            wmain->main_line.line_number++;
        }
        if (p) {
            char line[MAXLINE];

            wscrl(wmain->win, -1);
            print_buffer(line, MAXLINE, p);
            mvwprintw(wmain->win, 0, 0, "%s", line);

            /* deselect previous line and highlight next at top */
            mvwchgat(wmain->win, 1, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain->win, 0, 0, -1, A_NORMAL, 1, NULL);
        }
    } else if (wmain->selection_line > 0) {
         int screen_line = wmain->selection_line - wmain->top;

         /* deselect previous line and highlight next */
         if (wmain->subwindow.win && screen_line >= wmain->subwindow.top &&
             screen_line < wmain->subwindow.top + wmain->subwindow.num_lines) {
             int subline = screen_line - wmain->subwindow.top;

             mvwchgat(wmain->win, screen_line, 0, -1, GET_ATTR(lw, subline), 0, NULL);
             mvwchgat(wmain->win, screen_line - 1, 0, -1, subline == 0 ? A_NORMAL :
                      GET_ATTR(lw, subline - 1), 1, NULL);
         } else {
             mvwchgat(wmain->win, screen_line, 0, -1, A_NORMAL, 0, NULL);
             mvwchgat(wmain->win, screen_line - 1, 0, -1, A_NORMAL, 1, NULL);
         }
        wmain->selection_line--;
    }
    wrefresh(wmain->win);
}

void handle_keydown(int num_lines)
{
    if (!check_line()) return;

    if (!interactive) {
        set_interactive(true, num_lines);
    }

    /* scroll screen if the selection bar is at the bottom */
    if (wmain->selection_line - wmain->top == num_lines - 1) {
        struct packet *p = vector_get_data(packets, ++wmain->selection_line);

        wmain->top++;
        if (wmain->subwindow.win) {
            wmain->subwindow.top--;
            wmain->main_line.line_number--;
        }
        if (p) {
            char line[MAXLINE];

            wscrl(wmain->win, 1);
            print_buffer(line, MAXLINE, p);
            mvwprintw(wmain->win, num_lines - 1, 0, "%s", line);

            /* deselect previous line and highlight next line at bottom */
            mvwchgat(wmain->win, num_lines - 2, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain->win, num_lines - 1, 0, -1, A_NORMAL, 1, NULL);
        }
    } else {
        int screen_line = wmain->selection_line - wmain->top;

        /* deselect previous line and highlight next */
        if (wmain->subwindow.win && screen_line + 1 >= wmain->subwindow.top &&
            screen_line + 1 < wmain->subwindow.top + wmain->subwindow.num_lines) {
            int subline = screen_line - wmain->subwindow.top;

            mvwchgat(wmain->win, screen_line, 0, -1, subline == -1 ? A_NORMAL :
                     GET_ATTR(lw, subline), 0, NULL);
            mvwchgat(wmain->win, screen_line + 1, 0, -1, GET_ATTR(lw, subline + 1), 1, NULL);
        } else {
            mvwchgat(wmain->win, screen_line, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain->win, screen_line + 1, 0, -1, A_NORMAL, 1, NULL);
        }
        wmain->selection_line++;
    }
    wrefresh(wmain->win);
}

void scroll_page(int num_lines)
{
    if (!interactive) {
        set_interactive(true, num_lines);
    }
    if (num_lines > 0) { /* scroll page down */
        if (vector_size(packets) <= num_lines) {
            mvwchgat(wmain->win, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 0, NULL);
            wmain->selection_line = vector_size(packets) - 1;
            mvwchgat(wmain->win, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 1, NULL);
        } else {
            int bottom = wmain->top + num_lines - 1;

            mvwchgat(wmain->win, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 0, NULL);
            wmain->selection_line += num_lines;
            if (bottom + num_lines > vector_size(packets) - 1) {
                int scroll = vector_size(packets) - bottom - 1;

                wscrl(wmain->win, scroll);
                wmain->top += scroll;
                if (wmain->subwindow.win) {
                    wmain->subwindow.top -= scroll;
                    wmain->main_line.line_number -= scroll;
                }
                if (wmain->selection_line >= vector_size(packets)) {
                    wmain->selection_line = vector_size(packets) - 1;
                }
                print_lines(bottom + 1, vector_size(packets), vector_size(packets) - scroll - wmain->top);
            } else {
                wmain->top += num_lines;
                if (wmain->subwindow.win) {
                    wmain->subwindow.top -= num_lines;
                    wmain->main_line.line_number -= num_lines;
                }
                wscrl(wmain->win, num_lines);
                print_lines(wmain->top, wmain->top + num_lines, 0);
            }
            mvwchgat(wmain->win, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 1, NULL);
        }
    } else { /* scroll page up */
        if (vector_size(packets) <= abs(num_lines)) {
            mvwchgat(wmain->win, wmain->selection_line, 0, -1, A_NORMAL, 0, NULL);
            wmain->selection_line = 0;
            mvwchgat(wmain->win, 0, 0, -1, A_NORMAL, 1, NULL);
        } else {
            mvwchgat(wmain->win, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 0, NULL);
            wmain->selection_line += num_lines;
            if (wmain->top + num_lines < 0) {
                wscrl(wmain->win, -wmain->top);
                wmain->top = 0;
                if (wmain->selection_line < 0) {
                    wmain->selection_line = 0;
                }
                print_lines(wmain->top, wmain->top - num_lines, 0);
            } else {
                wscrl(wmain->win, num_lines);
                wmain->top += num_lines;
                if (wmain->subwindow.win) {
                    wmain->subwindow.top -= num_lines;
                    wmain->main_line.line_number -= num_lines;
                }
                print_lines(wmain->top, wmain->top - num_lines, 0);
            }
            mvwchgat(wmain->win, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 1, NULL);
        }
    }
    wrefresh(wmain->win);
}

void set_interactive(bool interactive_mode, int num_lines)
{
    if (!vector_size(packets)) return;

    if (interactive_mode) {
        interactive = true;
        wmain->selection_line = wmain->top;

        /* print selection bar */
        mvwchgat(wmain->win, 0, 0, -1, A_NORMAL, 1, NULL);
        wrefresh(wmain->win);
    } else {
        if (wmain->subwindow.win) {
            delete_subwindow();
            wmain->main_line.selected = false;
        }
        if (wmain->outy >= num_lines && capturing) {
            int c = vector_size(packets) - 1;

            werase(wmain->win);

            /* print the new lines stored in vector from bottom to top of screen */
            for (int i = num_lines - 1; i >= 0; i--, c--) {
                struct packet *p;
                char buffer[MAXLINE];

                p = vector_get_data(packets, c);
                print_buffer(buffer, MAXLINE, p);
                mvwprintw(wmain->win, i, 0, "%s", buffer);
            }
            wmain->top = c + 1;
        } else {
            /* remove selection bar */
            mvwchgat(wmain->win, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 0, NULL);
        }
        interactive = false;
        wrefresh(wmain->win);
    }
}

/*
 * Prints lines in the interval [from, to). 'y' specifies where on the screen it
 * will start to print. Returns how many lines are actually printed.
 */
int print_lines(int from, int to, int y)
{
    int c = 0;

    while (from < to) {
        struct packet *p;
        char buffer[MAXLINE];

        p = vector_get_data(packets, from);
        if (!p) break;
        print_buffer(buffer, MAXLINE, p);
        mvwprintw(wmain->win, y++, 0, "%s", buffer);
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

void print_status()
{
    mvwprintw(wstatus, 0, 0, "F1");
    wattron(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "%-6s", "Help");
    wattroff(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "F2");
    wattron(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "%-6s", "Start");
    wattroff(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "F3");
    wattron(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "%-6s", "Stop");
    wattroff(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "F4");
    wattron(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "%-6s", "Load");
    wattroff(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "F5");
    wattron(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "%-6s", "Save");
    wattroff(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "F6");
    wattron(wstatus, COLOR_PAIR(2));
    wprintw(wstatus, "%-6s", "Views");
    wattroff(wstatus, COLOR_PAIR(2));
    wrefresh(wstatus);
}

void print_packet(struct packet *p)
{
    int mx = getmaxx(wmain->win);
    char buf[mx];

    print_buffer(buf, mx, p);
    print(buf);
}

void print_file()
{
    int my = getmaxy(wmain->win);

    capturing = false;
    for (int i = 0; i < vector_size(packets) && i < my; i++) {
        print_packet(vector_get_data(packets, i));
    }
    set_interactive(true, -1);
}

/* write buffer to standard output */
void print(char *buf)
{
    int my;

    my = getmaxy(wmain->win);
    if (!interactive || (interactive && wmain->outy < my)) {
        scroll_window();
        mvwprintw(wmain->win, wmain->outy, 0, "%s", buf);
        wmain->outy++;
        wrefresh(wmain->win);
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

    if (prev_selection >= 0 && wmain->subwindow.win) {
        bool inside_subwin;

        inside_subwin = update_subwin_selection();
        if (inside_subwin) {
            p = vector_get_data(packets, prev_selection);
            print_protocol_information(p, prev_selection);
            return;
        }
    }
    screen_line = wmain->selection_line + wmain->scrolly - wmain->top;
    if (screen_line == wmain->main_line.line_number) {
        wmain->main_line.selected = !wmain->main_line.selected;
    } else {
        wmain->main_line.selected = true;

        /* the index to the selected line needs to be adjusted in case of an
           open wmain->subwindow */
        if (wmain->subwindow.win && screen_line > wmain->subwindow.top + wmain->scrolly) {
            wmain->main_line.line_number = screen_line - wmain->subwindow.num_lines;
            wmain->selection_line -= wmain->subwindow.num_lines;
        } else {
            wmain->main_line.line_number = screen_line;
        }
    }
    if (wmain->main_line.selected) {
        p = vector_get_data(packets, wmain->selection_line + wmain->scrolly);
        add_elements(p);
        print_protocol_information(p, wmain->selection_line + wmain->scrolly);
    } else {
        delete_subwindow();
    }
    prev_selection = wmain->selection_line + wmain->scrolly;
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
            add_payload(lw, header, p->eth.llc->payload, LLC_PAYLOAD_LEN(p));
        }
    } else {
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
    {
        uint16_t len = TCP_PAYLOAD_LEN(p);

        header = ADD_HEADER(lw, "Transmission Control Protocol (TCP)", selected[TRANSPORT], TRANSPORT);
        if (p->eth.ethertype == ETH_P_IP) {
            add_tcp_information(lw, header, &p->eth.ip->tcp, selected[SUBLAYER]);
            add_app_elements(&p->eth.ip->tcp.data, len);
        } else {
            add_tcp_information(lw, header, &p->eth.ipv6->tcp, selected[SUBLAYER]);
            add_app_elements(&p->eth.ipv6->tcp.data, len);
        }
        break;
    }
    case IPPROTO_UDP:
    {
        uint16_t len = UDP_PAYLOAD_LEN(p);

        header = ADD_HEADER(lw, "User Datagram Protocol (UDP)", selected[TRANSPORT], TRANSPORT);
        if (p->eth.ethertype == ETH_P_IP) {
            add_udp_information(lw, header, &p->eth.ip->udp);
            add_app_elements(&p->eth.ip->udp.data, len);
        } else {
            add_udp_information(lw, header, &p->eth.ipv6->udp);
            add_app_elements(&p->eth.ipv6->udp.data, len);
        }
        break;
    }
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
    case IPPROTO_PIM:
        header = ADD_HEADER(lw, "Protocol Independent Multicast (PIM)", selected[PIM], PIM);
        if (p->eth.ethertype == ETH_P_IP) {
            add_pim_information(lw, header, &p->eth.ip->pim, selected[SUBLAYER]);
        } else {
            add_pim_information(lw, header, &p->eth.ipv6->pim, selected[SUBLAYER]);
        }
        break;
    default:
        /* unknown transport layer payload */
        header = ADD_HEADER(lw, "Data", selected[APPLICATION], APPLICATION);
        if (p->eth.ethertype == ETH_P_IP) {
            add_payload(lw, header, p->eth.ip->payload, IP_PAYLOAD_LEN(p));
        } else {
            add_payload(lw, header, p->eth.ipv6->payload, IP_PAYLOAD_LEN(p));
        }
    }
}

void add_app_elements(struct application_info *info, uint16_t len)
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
        if (len) {
            header = ADD_HEADER(lw, "Data", selected[APPLICATION], APPLICATION);
            add_payload(lw, header, info->payload, len);
        }
        break;
    }
}

void print_protocol_information(struct packet *p, int lineno)
{
    /* Delete old subwindow. TODO: Don't use a subwindow for this */
    if (wmain->subwindow.win) {
        delete_subwindow();
    }

    /* print information in subwindow */
    create_subwindow(lw->size + 1, lineno);
    RENDER(lw, wmain->subwindow.win);

    int subline = wmain->selection_line - wmain->top - wmain->subwindow.top;
    if (subline >= 0) {
        mvwchgat(wmain->win, wmain->selection_line - wmain->top, 0, -1, GET_ATTR(lw, subline), 1, NULL);
    } else {
        mvwchgat(wmain->win, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 1, NULL);
    }
    touchwin(wmain->win);
    wrefresh(wmain->subwindow.win);
}

void create_subwindow(int num_lines, int lineno)
{
    int mx, my;
    int start_line;
    int c;

    getmaxyx(wmain->win, my, mx);
    start_line = lineno - wmain->top;
    c = lineno + 1;
    if (num_lines >= my) num_lines = my - 1;

    /* if there is not enough space for the information to be printed, the
        screen needs to be scrolled to make room for all the lines */
    if (my - (start_line + 1) < num_lines) {
        wmain->scrolly = num_lines - (my - (start_line + 1));
        wscrl(wmain->win, wmain->scrolly);
        start_line -= wmain->scrolly;
        wmain->selection_line -= wmain->scrolly;
        wrefresh(wmain->win);
    }

    /* make space for protocol specific information */
    wmain->subwindow.win = derwin(wmain->win, num_lines, mx, start_line + 1, 0);
    wmain->subwindow.top = start_line + 1;
    wmain->subwindow.num_lines = num_lines;
    wmove(wmain->win, start_line + 1, 0);
    wclrtobot(wmain->win); /* clear everything below selection bar */
    wmain->outy = start_line + num_lines + 1;

    if (!wmain->scrolly) {
        wmain->outy += print_lines(c, wmain->top + my, wmain->outy);
    }
    wrefresh(wmain->win);
}

void delete_subwindow()
{
    int my;
    int screen_line;

    my = getmaxy(wmain->win);
    screen_line = wmain->selection_line - wmain->top;
    delwin(wmain->subwindow.win);
    wmain->subwindow.win = NULL;
    wmain->subwindow.num_lines = 0;
    werase(wmain->win);

    /*
     * Print the entire screen. This can be optimized to just print the lines
     * that are below the selected line
     */
    wmain->outy = print_lines(wmain->top, wmain->top + my, 0);

    if (wmain->scrolly) {
        screen_line += wmain->scrolly;
        wmain->selection_line += wmain->scrolly;
        wmain->scrolly = 0;
    }
    mvwchgat(wmain->win, screen_line, 0, -1, A_NORMAL, 1, NULL);
    wrefresh(wmain->win);
}

/*
 * Checks if wmain->selection_line is inside the subwindow, and if that's the case, updates the
 * selection status of the selectable subwindow line.
 *
 * Returns true if it's inside the subwindow, else false.
 */

bool update_subwin_selection()
{
    int screen_line;

    screen_line = wmain->selection_line - wmain->top;
    if (screen_line >= wmain->subwindow.top &&
        screen_line < wmain->subwindow.top + wmain->subwindow.num_lines) {
        int subline;
        int32_t data;

        subline = screen_line - wmain->subwindow.top;
        data = GET_DATA(lw, subline);
        SET_EXPANDED(lw, subline, !GET_EXPANDED(lw, subline));
        if (data >= 0 && data < NUM_LAYERS) {
            selected[data] = GET_EXPANDED(lw, subline);
        }
        return true;
    }
    return false;
}
