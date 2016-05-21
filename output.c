#include <string.h>
#include <signal.h>
#include <linux/igmp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include "misc.h"
#include "output.h"
#include "list.h"
#include "error.h"
#include "util.h"
#include "vector.h"
#include "ui_protocols.h"

#define HEADER_HEIGHT 4
#define STATUS_HEIGHT 1
#define KEY_ESC 27
#define MAX_SELECTABLE 4
#define ETH_WINSIZE 4
#define ARP_WINSIZE 9
#define IP_WINSIZE 13
#define TCP_WINSIZE 10
#define UDP_WINSIZE 5
#define IGMP_WINSIZE 6

/* struct subwin { */
/*     int top; */
/*     int bottom; */
/*     WINDOW *wsub; */
/*     bool selected[MAX_SELECTABLE]; */
/* }; */

/* struct line { */
/*     bool selected; */
/*     struct subwin win; */
/* } *line_info; */


static struct line_info {
    bool selected;
    char *text;
    struct packet *p;
} *line;

static struct subwin_info {
    WINDOW *win;
    unsigned int top;
    unsigned int num_lines;
    struct line_info line;
} *subwindow;

bool numeric = true;
static WINDOW *wheader;
static WINDOW *wmain;
static WINDOW *wstatus;
static int outy = 0;
static bool interactive = false;
static int selection_line = 0;
static int top = 0; /* index to top of screen */

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

/* Print selected packet information in a subwindow */
static void create_subwindow(int num_lines, int lineno);
static void delete_subwindow();
static bool update_subwin_selection(int lineno);
static int calculate_subwin_size(struct packet *p, int screen_line);
static int calculate_applayer_size(struct application_info *info, int screen_line);
static void print_selected_packet();
static void print_protocol_information(struct packet *p, int lineno);
static void print_ethernet_verbose(struct packet *p, int lineno, int y);
static void print_arp_verbose(struct packet *p, int lineno, int y);
static void print_ip_verbose(struct ip_info *ip, int lineno, int y);
static void print_udp_verbose(struct ip_info *ip, int lineno, int y);
static void print_tcp_verbose(struct ip_info *ip, int lineno, int y);
static void print_app_protocol(struct application_info *info, int lineno, int y);
static void print_dns_verbose(struct dns_info *dns, int lineno, int y);
static void print_dns_soa(struct dns_info *info, int i, int lineno, int y, int x);
static void print_nbns_verbose(struct nbns_info *nbns, int lineno, int y);
static void print_icmp_verbose(struct ip_info *ip, int lineno, int y);
static void print_igmp_verbose(struct ip_info *info, int lineno, int y);
static void print_ssdp_verbose(list_t *ssdp, int lineno, int y);
static void print_http_verbose(struct http_info *http);

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
    subwindow = NULL;
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

    if (subwindow) {
        num_lines += subwindow->num_lines - 1;
    }
    if (selection_line < vector_size() + num_lines - 1) {
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
    if (!check_line(lines)) return;

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
    int mx = getmaxx(wmain);
    char buf[mx];

    print_buffer(buf, mx, p);
    print(buf);
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
    subwindow->win = derwin(wmain, num_lines, mx, start_line + 1, 0);
    subwindow->top = start_line + 1;
    subwindow->num_lines = num_lines;
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
    delwin(subwindow->win);
    subwindow = NULL;
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
 * Print more information about a packet when selected. This will print more
 * details about the specific protocol headers and payload.
 */
void print_selected_packet()
{
    int screen_line;
    struct packet *p;
    static int prev_selection = -1;

    if (prev_selection >= 0) {
        screen_line = prev_selection - top;
        if (subwindow) {
            bool inside_subwin;

            inside_subwin = update_subwin_selection(prev_selection);
            if (inside_subwin) {
                p = vector_get_data(prev_selection);
                print_protocol_information(p, prev_selection);
                return;
            }
        }
    }
    screen_line = selection_line - top;
    line[screen_line].selected = !line[screen_line].selected;
    if (line[screen_line].selected) {
        p = vector_get_data(selection_line);
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
 * TODO: How to update the subwindow's selectable elements when there are some
 * elements that are already selected?
 */
bool update_subwin_selection(int lineno)
{
    int screen_line;
    int sub_start_line;

    screen_line = selection_line - top;
    sub_start_line = lineno - top;
    if (screen_line >= subwindow->top &&
        screen_line <= subwindow->top + subwindow->num_lines) {
        int subline;
        
        subline = screen_line - subwindow->top;
        if (subline < MAX_SELECTABLE) {
            //line[sub_start_line].win.selected[subline] = !line[sub_start_line].win.selected[subline];
        }
        return true;
    }
    return false;
}

/* Calculates size of subwindow */
int calculate_subwin_size(struct packet *p, int screen_line)
{
    int size = 1;
 
    if (line[screen_line].win.selected[0]) {
        size += ETH_WINSIZE + 1;
    } else {
        size++;
    }
    if (p->eth.ethertype == ETH_P_ARP) {
        if (line[screen_line].win.selected[1]) {
            size += ARP_WINSIZE;
        } else {
            size++;
        }
    } else if (p->eth.ethertype == ETH_P_IP) {
        if (line[screen_line].win.selected[1]) {
            size += IP_WINSIZE + 1;
        } else {
            size++;
        }
        switch (p->eth.ip->protocol) {
        case IPPROTO_TCP:
            if (line[screen_line].win.selected[2]) {
                size += TCP_WINSIZE;
            }
            size += calculate_applayer_size(&p->eth.ip->tcp.data, screen_line);
            break;
        case IPPROTO_UDP:
            if (line[screen_line].win.selected[2]) {
                size += UDP_WINSIZE;
            }
            size += calculate_applayer_size(&p->eth.ip->udp.data, screen_line);
            break;
        case IPPROTO_ICMP:
            if (line[screen_line].win.selected[2]) {
                if (p->eth.ip->icmp.type == ICMP_ECHOREPLY ||
                    p->eth.ip->icmp.type == ICMP_ECHO) {
                    size += 7;
                } else {
                    size += 5;
                }
            } else {
                size++;
            }
            break;
        case IPPROTO_IGMP:
            if (line[screen_line].win.selected[2]) {
                size += IGMP_WINSIZE;
            } else {
                size++;
            }
            break;
        default:
            break;
        }
    }
    return size;
}

int calculate_applayer_size(struct application_info *info, int screen_line)
{
    int size = 1;

    if (line[screen_line].win.selected[3]) {
        switch (info->utype) {
        case DNS:
        {
            int records = 0;
            
            /* number of resource records */
            for (int i = 1; i < 4; i++) {
                records += info->dns->section_count[i];
            }
            size += (info->dns->section_count[NSCOUNT] ? 18 + records : 10 + records);
            break;
        }
        case NBNS:
        {
            int records = 0;

            /* number of resource records */
            for (int i = 1; i < 4; i++) {
                records += info->nbns->section_count[i];
            }
            size += (records ? 11 + records : 10);
            break;
        }
        case HTTP:
            break;
        case SSDP:
            size += list_size(info->ssdp) + 2;
            break;
        default:
            break;
        }
    } else {
        size++;
    }
    return size;
}

void print_protocol_information(struct packet *p, int lineno)
{
    int screen_line = lineno - top;
    int size = 0;
    int y = 0;

    size = calculate_subwin_size(p, lineno);

    /* Delete old subwindow. TODO: Possible to just resize? */
    if (subwindow) {
        delete_subwindow();
    }

    /* print information in subwindow */
    create_subwindow(size, lineno);
    if (line[screen_line].win.selected[0]) {
        mvwprintw(subwindow->win, y++, 2, "- Ethernet header");
        print_ethernet_verbose(p, lineno, y);
        y += ETH_WINSIZE;
    } else {
        mvwprintw(subwindow->win, y++, 2, "+ Ethernet header");
    }
    if (p->eth.ethertype == ETH_P_ARP) {
        if (line[screen_line].win.selected[1]) {
            mvwprintw(subwindow->win, y++, 2, "- ARP header");
            print_arp_verbose(p, lineno, y);
        } else {
            mvwprintw(subwindow->win, y, 2, "+ ARP header");
        }
    } else if (p->eth.ethertype == ETH_P_IP) {
        if (line[screen_line].win.selected[1]) {
            mvwprintw(subwindow->win, y++, 2, "- IP header");
            print_ip_verbose(p->eth.ip, lineno, y);
            y += IP_WINSIZE;
        } else {
            mvwprintw(subwindow->win, y++, 2, "+ IP header");
        }
        switch (p->eth.ip->protocol) {
        case IPPROTO_TCP:
            if (line[screen_line].win.selected[2]) {
                mvwprintw(subwindow->win, y++, 2, "- TCP header");
                print_tcp_verbose(p->eth.ip, lineno, y);
                y += TCP_WINSIZE;
            } else {
                mvwprintw(subwindow->win, y++, 2, "+ TCP header");
            }
            print_app_protocol(&p->eth.ip->tcp.data, lineno, y);
            break;
        case IPPROTO_UDP:
            if (line[screen_line].win.selected[2]) {
                mvwprintw(subwindow->win, y++, 2, "- UDP header");
                print_udp_verbose(p->eth.ip, lineno, y);
                y += UDP_WINSIZE;
            } else {
                mvwprintw(subwindow->win, y++, 2, "+ UDP header");
            }
            print_app_protocol(&p->eth.ip->udp.data, lineno, y);
            break;
        case IPPROTO_ICMP:
            if (line[screen_line].win.selected[2]) {
                mvwprintw(subwindow->win, y++, 2, "- ICMP header");
                print_icmp_verbose(p->eth.ip, lineno, y);
            } else {
                mvwprintw(subwindow->win, y++, 2, "+ ICMP header");
            }
            break;
        case IPPROTO_IGMP:
            if (line[screen_line].win.selected[2]) {
                mvwprintw(subwindow->win, y++, 2, "- IGMP header");
                print_igmp_verbose(p->eth.ip, lineno, y);
            } else {
                mvwprintw(subwindow->win, y++, 2, "+ IGMP header");
            }
            break;
        }        
    }
    mvwchgat(wmain, selection_line - top, 0, -1, A_NORMAL, 1, NULL);
    touchwin(wmain);
    wrefresh(subwindow->win);
}


void print_app_protocol(struct application_info *info, int lineno, int y)
{
    int screen_line = lineno - top;

    switch (info->utype) {
    case DNS:
        if (line[screen_line].win.selected[3]) {
            mvwprintw(subwindow->win, y++, 2, "- DNS header");
            print_dns_verbose(info->dns, lineno, y);
        } else {
            mvwprintw(subwindow->win, y++, 2, "+ DNS header");
        }
        break;
    case NBNS:
        if (line[screen_line].win.selected[3]) {
            mvwprintw(subwindow->win, y++, 2, "- NBNS header");
            print_nbns_verbose(info->nbns, lineno, y);
        } else {
            mvwprintw(subwindow->win, y++, 2, "+ NBNS header");
        }
        break;
    case SSDP:
        if (line[screen_line].win.selected[3]) {
            mvwprintw(subwindow->win, y++, 2, "- SSDP header");
            print_ssdp_verbose(info->ssdp, lineno, y);
        } else {
            mvwprintw(subwindow->win, y++, 2, "+ SSDP header");
        }
        break;
    case HTTP:
        if (line[screen_line].win.selected[3]) {
            mvwprintw(subwindow->win, y++, 2, "- HTTP header");
            print_http_verbose(info->http);
        } else {
            mvwprintw(subwindow->win, y++, 2, "+ HTTP header");
        }
        break;
    default:
        break;
    }
}

void print_ethernet_verbose(struct packet *p, int lineno, int y)
{
    int screen_line = lineno - top;
    char src[HW_ADDRSTRLEN];
    char dst[HW_ADDRSTRLEN];

    snprintf(src, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             p->eth.mac_src[0], p->eth.mac_src[1], p->eth.mac_src[2],
             p->eth.mac_src[3], p->eth.mac_src[4], p->eth.mac_src[5]);
    snprintf(dst, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             p->eth.mac_dst[0], p->eth.mac_dst[1], p->eth.mac_dst[2],
             p->eth.mac_dst[3], p->eth.mac_dst[4], p->eth.mac_dst[5]);
    mvwprintw(subwindow->win, y, 4, "MAC source: %s", src);
    mvwprintw(subwindow->win, ++y, 4, "MAC destination: %s", dst);
    mvwprintw(subwindow->win, ++y, 4, "Ethertype: 0x%x", p->eth.ethertype);
}

void print_arp_verbose(struct packet *p, int lineno, int y)
{
    int screen_line = lineno - top;

    mvwprintw(subwindow->win, y, 4, "Hardware type: %d (%s)", p->eth.arp->ht, get_arp_hardware_type(p->eth.arp->ht));
    mvwprintw(subwindow->win, ++y, 4, "Protocol type: 0x%x (%s)", p->eth.arp->pt, get_arp_protocol_type(p->eth.arp->pt));
    mvwprintw(subwindow->win, ++y, 4, "Hardware size: %d", p->eth.arp->hs);
    mvwprintw(subwindow->win, ++y, 4, "Protocol size: %d", p->eth.arp->ps);
    mvwprintw(subwindow->win, ++y, 4, "Opcode: %d (%s)", p->eth.arp->op, get_arp_opcode(p->eth.arp->op));
    mvwprintw(subwindow->win, ++y, 0, "");
    mvwprintw(subwindow->win, ++y, 4, "Sender IP: %-15s  HW: %s", p->eth.arp->sip, p->eth.arp->sha);
    mvwprintw(subwindow->win, ++y, 4, "Target IP: %-15s  HW: %s", p->eth.arp->tip, p->eth.arp->tha);
}

void print_ip_verbose(struct ip_info *ip, int lineno, int y)
{
    int screen_line = lineno - top;

    mvwprintw(subwindow->win, y, 4, "Version: %u", ip->version);
    mvwprintw(subwindow->win, ++y, 4, "Internet Header Length (IHL): %u", ip->ihl);
    mvwprintw(subwindow->win, ++y, 4, "Differentiated Services Code Point (DSCP): %u", ip->dscp);
    mvwprintw(subwindow->win, ++y, 4, "Explicit Congestion Notification (ECN): %u", ip->ecn);
    mvwprintw(subwindow->win, ++y, 4, "Total length: %u", ip->length);
    mvwprintw(subwindow->win, ++y, 4, "Identification: %u", ip->id);
    mvwprintw(subwindow->win, ++y, 4, "Flags: %u%u%u", ip->foffset & 0x80, ip->foffset & 0x40, ip->foffset & 0x20);
    mvwprintw(subwindow->win, ++y, 4, "Time to live: %u", ip->ttl);
    mvwprintw(subwindow->win, ++y, 4, "Protocol: %u", ip->protocol);
    mvwprintw(subwindow->win, ++y, 4, "Checksum: %u", ip->checksum);
    mvwprintw(subwindow->win, ++y, 4, "Source IP address: %s", ip->src);
    mvwprintw(subwindow->win, ++y, 4, "Destination IP address: %s", ip->dst);
}

void print_icmp_verbose(struct ip_info *ip, int lineno, int y)
{
    int screen_line = lineno - top;

    mvwprintw(subwindow->win, y, 4, "Type: %d (%s)", ip->icmp.type, get_icmp_type(ip->icmp.type));
    switch (ip->icmp.type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        mvwprintw(subwindow->win, ++y, 4, "Code: %d", ip->icmp.code);
        break;
    case ICMP_DEST_UNREACH:
        mvwprintw(subwindow->win, ++y, 4, "Code: %d (%s)", ip->icmp.code, get_icmp_dest_unreach_code(ip->icmp.code));
        break;
    default:
        break;
    }
    mvwprintw(subwindow->win, ++y, 4, "Checksum: %d", ip->icmp.checksum);
    if (ip->icmp.type == ICMP_ECHOREPLY || ip->icmp.type == ICMP_ECHO) {
        mvwprintw(subwindow->win, ++y, 4, "Identifier: 0x%x", ip->icmp.echo.id);
        mvwprintw(subwindow->win, ++y, 4, "Sequence number: %d", ip->icmp.echo.seq_num);
    }
}

void print_igmp_verbose(struct ip_info *info, int lineno, int y)
{
    int screen_line = lineno - top;

    mvwprintw(subwindow->win, y, 4, "Type: %d (%s) ", info->igmp.type, get_igmp_type(info->icmp.type));
    if (info->igmp.type == IGMP_HOST_MEMBERSHIP_QUERY) {
        if (!strcmp(info->igmp.group_addr, "0.0.0.0")) {
            mvwprintw(subwindow->win, y, 4, "General query", info->igmp.type, get_igmp_type(info->icmp.type));
        } else {
            mvwprintw(subwindow->win, y, 4, "Group-specific query", info->igmp.type, get_igmp_type(info->icmp.type));
        }
    }
    mvwprintw(subwindow->win, ++y, 4, "Max response time: %d seconds", info->igmp.max_resp_time / 10);
    mvwprintw(subwindow->win, ++y, 4, "Checksum: %d", info->igmp.checksum);
    mvwprintw(subwindow->win, ++y, 4, "Group address: %s", info->igmp.group_addr);
    mvwprintw(subwindow->win, ++y, 0, "");
}

void print_udp_verbose(struct ip_info *ip, int lineno, int y)
{
    int screen_line = lineno - top;
    
    mvwprintw(subwindow->win, y, 4, "Source port: %u", ip->udp.src_port);
    mvwprintw(subwindow->win, ++y, 4, "Destination port: %u", ip->udp.dst_port);
    mvwprintw(subwindow->win, ++y, 4, "Length: %u", ip->udp.len);
    mvwprintw(subwindow->win, ++y, 4, "Checksum: %u", ip->udp.checksum);
}

void print_tcp_verbose(struct ip_info *ip, int lineno, int y)
{
    int screen_line = lineno - top;
    
    mvwprintw(subwindow->win, y, 4, "Source port: %u", ip->tcp.src_port);
    mvwprintw(subwindow->win, ++y, 4, "Destination port: %u", ip->tcp.dst_port);
    mvwprintw(subwindow->win, ++y, 4, "Sequence number: %u", ip->tcp.seq_num);
    mvwprintw(subwindow->win, ++y, 4, "Acknowledgment number: %u", ip->tcp.ack_num);
    mvwprintw(subwindow->win, ++y, 4, "Data offset: %u", ip->tcp.offset);
    mvwprintw(subwindow->win, ++y, 4, "Flags: %u%u%u%u%u%u%u%u%u",
              ip->tcp.ns, ip->tcp.cwr, ip->tcp.ece, ip->tcp.urg, ip->tcp.ack,
              ip->tcp.psh, ip->tcp.rst, ip->tcp.syn, ip->tcp.fin);
    mvwprintw(subwindow->win, ++y, 4, "Window size: %u", ip->tcp.window);
    mvwprintw(subwindow->win, ++y, 4, "Checksum: %u", ip->tcp.checksum);
    mvwprintw(subwindow->win, ++y, 4, "Urgent pointer: %u", ip->tcp.urg_ptr);
}

void print_dns_verbose(struct dns_info *dns, int lineno, int y)
{
    int records = 0;
    int screen_line = lineno - top;

    /* number of resource records */
    for (int i = 1; i < 4; i++) {
        records += dns->section_count[i];
    }
    mvwprintw(subwindow->win, y, 4, "ID: 0x%x", dns->id);
    mvwprintw(subwindow->win, ++y, 4, "QR: %d (%s)", dns->qr, dns->qr ? "DNS Response" : "DNS Query");
    mvwprintw(subwindow->win, ++y, 4, "Opcode: %d (%s)", dns->opcode, get_dns_opcode(dns->opcode));
    mvwprintw(subwindow->win, ++y, 4, "Flags: %d%d%d%d", dns->aa, dns->tc, dns->rd, dns->ra);
    mvwprintw(subwindow->win, ++y, 4, "Rcode: %d (%s)", dns->rcode, get_dns_rcode(dns->rcode));
    mvwprintw(subwindow->win, ++y, 4, "Question: %d, Answer: %d, Authority: %d, Additional records: %d",
              dns->section_count[QDCOUNT], dns->section_count[ANCOUNT],
              dns->section_count[NSCOUNT], dns->section_count[ARCOUNT]);
    mvwprintw(subwindow->win, ++y, 0, "");
    for (int i = dns->section_count[QDCOUNT]; i > 0; i--) {
        mvwprintw(subwindow->win, ++y, 4, "QNAME: %s, QTYPE: %s, QCLASS: %s",
                  dns->question.qname, get_dns_type_extended(dns->question.qtype),
                  get_dns_class_extended(dns->question.qclass));
    }
    if (records) {
        int mx;
        int len;

        mx = getmaxx(wmain);
        mvwprintw(subwindow->win, ++y, 4, "Resource records:");
        len = get_max_namelen(dns->record, records);
        for (int i = 0; i < records; i++) {
            char buffer[mx];
            bool soa = false;

            snprintf(buffer, mx, "%-*s", len + 4, dns->record[i].name);
            snprintcat(buffer, mx, "%-6s", get_dns_class(dns->record[i].class));
            snprintcat(buffer, mx, "%-8s", get_dns_type(dns->record[i].type));
            print_dns_record(dns, i, buffer, mx, dns->record[i].type, &soa);
            mvwprintw(subwindow->win, ++y, 8, "%s", buffer);
            if (soa) {
                mvwprintw(subwindow->win, ++y, 0, "");
                print_dns_soa(dns, i, lineno, y + 1, 8);
            }
        }
    }
}

void print_dns_soa(struct dns_info *info, int i, int lineno, int y, int x)
{
    int screen_line = lineno - top;

    mvwprintw(subwindow->win, y, x, "mname: %s", info->record[i].rdata.soa.mname);
    mvwprintw(subwindow->win, ++y, x, "rname: %s", info->record[i].rdata.soa.rname);
    mvwprintw(subwindow->win, ++y, x, "Serial: %d", info->record[i].rdata.soa.serial);
    mvwprintw(subwindow->win, ++y, x, "Refresh: %d", info->record[i].rdata.soa.refresh);
    mvwprintw(subwindow->win, ++y, x, "Retry: %d", info->record[i].rdata.soa.retry);
    mvwprintw(subwindow->win, ++y, x, "Expire: %d", info->record[i].rdata.soa.expire);
    mvwprintw(subwindow->win, ++y, x, "Minimum: %d", info->record[i].rdata.soa.minimum);
}

void print_nbns_verbose(struct nbns_info *nbns, int lineno, int y)
{
    int records = 0;
    int screen_line = lineno - top;

    /* number of resource records */
    for (int i = 1; i < 4; i++) {
        records += nbns->section_count[i];
    }
    mvwprintw(subwindow->win, y, 0, "");
    mvwprintw(subwindow->win, ++y, 4, "ID: 0x%x", nbns->id);
    mvwprintw(subwindow->win, ++y, 4, "Response flag: %d (%s)", nbns->r, nbns->r ? "Response" : "Request");
    mvwprintw(subwindow->win, ++y, 4, "Opcode: %d (%s)", nbns->opcode, get_nbns_opcode(nbns->opcode));
    mvwprintw(subwindow->win, ++y, 4, "Flags: %d%d%d%d%d", nbns->aa, nbns->tc, nbns->rd, nbns->ra, nbns->broadcast);
    mvwprintw(subwindow->win, ++y, 4, "Rcode: %d (%s)", nbns->rcode, get_nbns_rcode(nbns->rcode));
    mvwprintw(subwindow->win, ++y, 4, "Question Entries: %d, Answer RRs: %d, Authority RRs: %d, Additional RRs: %d",
              nbns->section_count[QDCOUNT], nbns->section_count[ANCOUNT],
              nbns->section_count[NSCOUNT], nbns->section_count[ARCOUNT]);
    mvwprintw(subwindow->win, ++y, 0, "");

    /* question entry */
    if (nbns->section_count[QDCOUNT]) {
        mvwprintw(subwindow->win, ++y, 4, "Question name: %s, Question type: %s, Question class: IN (Internet)",
                  nbns->question.qname, get_nbns_type_extended(nbns->question.qtype));
    }

    if (records) {
        int mx;

        mx = getmaxx(wmain);
        mvwprintw(subwindow->win, ++y, 4, "Resource records:");
        for (int i = 0; i < records; i++) {
            char buffer[mx];

            snprintf(buffer, mx, "%s\t", nbns->record[i].rrname);
            snprintcat(buffer, mx, "IN\t");
            snprintcat(buffer, mx, "%s\t", get_nbns_type(nbns->record[i].rrtype));
            print_nbns_record(nbns, i, buffer, mx, nbns->record[i].rrtype);
            mvwprintw(subwindow->win, ++y, 8, "%s", buffer);
        }
    }
}


void print_ssdp_verbose(list_t *ssdp, int lineno, int y)
{
    const node_t *n;
    int screen_line = lineno - top;

    mvwprintw(subwindow->win, y, 0, "");
    n = list_begin(ssdp);
    while (n) {
        mvwprintw(subwindow->win, ++y, 4, "%s", (char *) list_data(n));
        n = list_next(n);
    }
    mvwprintw(subwindow->win, ++y, 0, "");
    touchwin(wmain);
    wrefresh(subwindow->win);
}

void print_http_verbose(struct http_info *http)
{

}
