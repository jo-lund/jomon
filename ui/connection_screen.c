#include <stdlib.h>
#include <arpa/inet.h>
#include "connection_screen.h"
#include "help_screen.h"
#include "menu.h"
#include "../decoder/tcp_analyzer.h"
#include "../decoder/packet.h"
#include "../decoder/packet_ip.h"
#include "../misc.h"
#include "../util.h"

#define ADDR_WIDTH 17
#define PORT_WIDTH 10
#define CONN_WIDTH 2 * ADDR_WIDTH + 2 * PORT_WIDTH
#define STATE_WIDTH 14
#define PACKET_WIDTH 8
#define BYTES_WIDTH 14
#define TOTAL_WIDTH CONN_WIDTH + STATE_WIDTH + PACKET_WIDTH + BYTES_WIDTH
#define AB_WIDTH TOTAL_WIDTH + 2 * PACKET_WIDTH + BYTES_WIDTH
#define CONN_HEADER 3
#define STATUS_HEIGHT 1

extern WINDOW *status;
extern main_menu *menu;

static void connection_screen_init(screen *s);
static void connection_screen_refresh(screen *s);
static void connection_screen_get_input(screen *s);
static void connection_screen_got_focus(screen *s __attribute__((unused)));
static void connection_screen_lost_focus(screen *s __attribute__((unused)));
static void connection_screen_render(connection_screen *cs);
static void update_connection(struct tcp_connection_v4 *c, bool new_connection);
static void print_all_connections(connection_screen *cs);
static void print_connection(connection_screen *cs, struct tcp_connection_v4 *conn, int y);
static void print_conn_header(connection_screen *cs);
static void print_status();
static void scroll_page(connection_screen *cs, int num_lines);

static screen_operations csop = {
    .screen_init = connection_screen_init,
    .screen_free = connection_screen_free,
    .screen_refresh = connection_screen_refresh,
    .screen_get_input = connection_screen_get_input,
    .screen_got_focus = connection_screen_got_focus,
    .screen_lost_focus = connection_screen_lost_focus,
};

connection_screen *connection_screen_create()
{
    connection_screen *cs;

    cs = malloc(sizeof(connection_screen));
    cs->base.op = &csop;
    connection_screen_init((screen *) cs);
    return cs;
}

void connection_screen_init(screen *s)
{
    int my, mx;
    connection_screen *cs = (connection_screen *) s;

    getmaxyx(stdscr, my, mx);
    cs->header = newwin(CONN_HEADER, mx, 0, 0);
    cs->base.win = newwin(my - CONN_HEADER - STATUS_HEIGHT, mx, CONN_HEADER, 0);
    cs->top = 0;
    cs->y = 0;
    cs->lines = my - CONN_HEADER - STATUS_HEIGHT;
    cs->screen_buf = vector_init(1024);
    scrollok(cs->base.win, TRUE);
    nodelay(cs->base.win, TRUE);
    keypad(cs->base.win, TRUE);
}

void connection_screen_free(screen *s)
{
    connection_screen *cs = (connection_screen *) s;

    delwin(cs->header);
    delwin(s->win);
    vector_free(cs->screen_buf, NULL);
    free(cs);
}

void connection_screen_got_focus(screen *s __attribute__((unused)))
{
    analyzer_subscribe(update_connection);
}

void connection_screen_lost_focus(screen *s __attribute__((unused)))
{
    analyzer_unsubscribe(update_connection);
}

void connection_screen_refresh(screen *s)
{
    connection_screen *cs = (connection_screen *) s;

    werase(s->win);
    werase(cs->header);
    cs->top = 0;
    cs->y = 0;
    vector_clear(cs->screen_buf, NULL);
    wbkgd(s->win, get_theme_colour(BACKGROUND));
    wbkgd(cs->header, get_theme_colour(BACKGROUND));
    connection_screen_render(cs);
}

void connection_screen_get_input(screen *s)
{
    connection_screen *cs = (connection_screen *) s;
    int c = wgetch(s->win);
    int my = getmaxy(s->win);

    switch (c) {
    case 'x':
    case KEY_ESC:
    case KEY_F(3):
        pop_screen();
        break;
    case KEY_F(1):
        push_screen(screen_cache_get(HELP_SCREEN));
        break;
    case KEY_F(2):
        push_screen((screen *) menu);
        break;
    case KEY_UP:
        if (cs->top > 0) {
            cs->top--;
            wscrl(s->win, -1);
            print_connection(cs, vector_get_data(cs->screen_buf, cs->top), 0);
            wrefresh(cs->base.win);
        }
        break;
    case KEY_DOWN:
        if (cs->top + cs->lines < vector_size(cs->screen_buf)) {
            cs->top++;
            wscrl(s->win, 1);
            print_connection(cs, vector_get_data(cs->screen_buf, cs->top + cs->lines - 1),
                             cs->lines - 1);
            wrefresh(cs->base.win);
        }
        break;
    case ' ':
    case KEY_NPAGE:
        scroll_page(cs, my);
        break;
    case 'b':
    case KEY_PPAGE:
        scroll_page(cs, -my);
        break;
    case 'q':
    case KEY_F(10):
        finish();
        break;
    default:
        break;
    }
}

void connection_screen_render(connection_screen *cs)
{
    hash_map_t *sessions = analyzer_get_sessions();

    if (hash_map_size(sessions)) {
        const hash_map_iterator *it = hash_map_first(sessions);

        while (it) {
            vector_push_back(cs->screen_buf, it->data);
            it = hash_map_next(sessions, it);
        }
    }
    touchwin(cs->header);
    touchwin(cs->base.win);
    print_conn_header(cs);
    print_all_connections(cs);
    print_status();
}

void update_connection(struct tcp_connection_v4 *c, bool new_connection)
{
    struct tcp_connection_v4 *conn = (struct tcp_connection_v4 *) c;
    connection_screen *cs = (connection_screen *) screen_cache_get(CONNECTION_SCREEN);

    werase(cs->header);
    print_conn_header(cs);
    if (new_connection) {
        vector_push_back(cs->screen_buf, conn);
        if (vector_size(cs->screen_buf) < cs->lines) {
            print_connection(cs, conn, cs->y);
            cs->y++;
            wrefresh(cs->base.win);
        }
    } else {
        int y = 0;

        while (y < cs->lines && cs->top + y < vector_size(cs->screen_buf)) {
            if (vector_get_data(cs->screen_buf, cs->top + y) == conn) {
                wmove(cs->base.win, y, 0);
                wclrtoeol(cs->base.win);
                print_connection(cs, conn, y);
                wrefresh(cs->base.win);
                break;
            }
            y++;
        }
    }
}

void print_conn_header(connection_screen *cs)
{
    int y = 0;

    printat(cs->header, y, 0, get_theme_colour(HEADER_TXT), "TCP connections");
    wprintw(cs->header,  ": %d", vector_size(cs->screen_buf));
    y += 2;
    mvwprintw(cs->header, y, 0, "IP address A");
    mvwprintw(cs->header, y, ADDR_WIDTH, "Port A");
    mvwprintw(cs->header, y, ADDR_WIDTH + PORT_WIDTH, "IP address B");
    mvwprintw(cs->header, y, 2 * ADDR_WIDTH + PORT_WIDTH, "Port B");
    mvwprintw(cs->header, y, CONN_WIDTH, "State");
    mvwprintw(cs->header, y, CONN_WIDTH + STATE_WIDTH, "Packets");
    mvwprintw(cs->header, y, CONN_WIDTH + STATE_WIDTH + PACKET_WIDTH, "Bytes");
    mvwprintw(cs->header, y, TOTAL_WIDTH, "Packets A -> B");
    mvwprintw(cs->header, y, TOTAL_WIDTH + 2 * PACKET_WIDTH, "Bytes A -> B");
    mvwprintw(cs->header, y, AB_WIDTH, "Packets A <- B");
    mvwprintw(cs->header, y, AB_WIDTH + 2 * PACKET_WIDTH, "Bytes A <- B");
    mvwchgat(cs->header, y, 0, -1, A_STANDOUT, 0, NULL);
    wrefresh(cs->header);
}

void print_all_connections(connection_screen *cs)
{
    int i = cs->top;

    while (cs->y < cs->lines && i < vector_size(cs->screen_buf)) {
        print_connection(cs, vector_get_data(cs->screen_buf, i), cs->y);
        cs->y++;
        i++;
    }
    wrefresh(cs->base.win);
}

void print_connection(connection_screen *cs, struct tcp_connection_v4 *conn, int y)
{
    char buf[MAXLINE];
    char srcaddr[INET_ADDRSTRLEN];
    char dstaddr[INET_ADDRSTRLEN];
    uint32_t bytes = 0;
    uint32_t addra = 0;
    uint32_t addrb = 0;
    uint32_t bytes_atob = 0;
    uint32_t bytes_btoa = 0;
    uint32_t packets_atob = 0;
    uint32_t packets_btoa = 0;
    const node_t *n = list_begin(conn->packets);
    struct packet *p;

    inet_ntop(AF_INET, &conn->endp->src, srcaddr, sizeof(srcaddr));
    inet_ntop(AF_INET, &conn->endp->dst, dstaddr, sizeof(dstaddr));
    snprintf(buf, MAXLINE, "%-*s%-*d%-*s%d", ADDR_WIDTH, srcaddr, PORT_WIDTH,
             conn->endp->src_port, ADDR_WIDTH, dstaddr, conn->endp->dst_port);
    p = list_data(n);
    addra = p->eth.ip->src;
    addrb = p->eth.ip->dst;
    while (n) {
        p = list_data(n);
        if (addra == p->eth.ip->src) {
            bytes_atob += get_packet_size(p);
            packets_atob++;
        } else if (addrb == p->eth.ip->src) {
            bytes_btoa += get_packet_size(p);
            packets_btoa++;
        }
        bytes += get_packet_size(p);
        n = list_next(n);
    }
    if (conn->state != ESTABLISHED && conn->state != SYN_SENT &&
        conn->state != SYN_RCVD) {
        printat(cs->base.win, y, 0, get_theme_colour(DISABLE), "%s", buf);
        printat(cs->base.win, y, CONN_WIDTH, get_theme_colour(DISABLE),
                "%s", analyzer_get_connection_state(conn->state));
        printat(cs->base.win, y, CONN_WIDTH + STATE_WIDTH, get_theme_colour(DISABLE),
                "%d", list_size(conn->packets));
        printat(cs->base.win, y, CONN_WIDTH + STATE_WIDTH + PACKET_WIDTH,
                get_theme_colour(DISABLE), "%s", format_bytes(bytes, buf, MAXLINE));
        printat(cs->base.win, y, TOTAL_WIDTH, get_theme_colour(DISABLE),
                "%d", packets_atob);
        printat(cs->base.win, y, TOTAL_WIDTH + 2 * PACKET_WIDTH, get_theme_colour(DISABLE),
                "%s", format_bytes(bytes_atob, buf, MAXLINE));
        printat(cs->base.win, y, AB_WIDTH, get_theme_colour(DISABLE),
                "%d", packets_btoa);
        printat(cs->base.win, y, AB_WIDTH + 2 * PACKET_WIDTH, get_theme_colour(DISABLE),
                "%s", format_bytes(bytes_btoa, buf, MAXLINE));
    } else {
        mvwprintw(cs->base.win, y, 0, "%s", buf);
        mvwprintw(cs->base.win, y, CONN_WIDTH, "%s",
                  analyzer_get_connection_state(conn->state));
        mvwprintw(cs->base.win, y, CONN_WIDTH + STATE_WIDTH, "%d",
                  list_size(conn->packets));
        mvwprintw(cs->base.win, y, CONN_WIDTH + STATE_WIDTH + PACKET_WIDTH, "%s",
                  format_bytes(bytes, buf, MAXLINE));
        mvwprintw(cs->base.win, y, TOTAL_WIDTH, "%d", packets_atob);
        mvwprintw(cs->base.win, y, TOTAL_WIDTH + 2 * PACKET_WIDTH, "%s",
                  format_bytes(bytes_atob, buf, MAXLINE));
        mvwprintw(cs->base.win, y, AB_WIDTH, "%d", packets_btoa);
        mvwprintw(cs->base.win, y, AB_WIDTH + 2 * PACKET_WIDTH, "%s",
                  format_bytes(bytes_btoa, buf, MAXLINE));
    }
}

void print_status()
{
    int colour = get_theme_colour(STATUS_BUTTON);

    werase(status);
    wbkgd(status, get_theme_colour(BACKGROUND));
    mvwprintw(status, 0, 0, "F1");
    printat(status, -1, -1, colour, "%-11s", "Help");
    wprintw(status, "F2");
    printat(status, -1, -1, colour, "%-11s", "Menu");
    wprintw(status, "F3");
    printat(status, -1, -1, colour, "%-11s", "Back");
    wprintw(status, "F10");
    printat(status, -1, -1, colour, "%-11s", "Quit");
    wrefresh(status);
}

void scroll_page(connection_screen *cs, int num_lines)
{
    int i = abs(num_lines);

    if (vector_size(cs->screen_buf) <= i) return;

    if (num_lines > 0) { /* scroll down */
        while (i > 0 && cs->top + cs->lines < vector_size(cs->screen_buf)) {
            cs->top++;
            i--;
        }
    } else { /* scroll up */
        while (i > 0 && cs->top > 0) {
            cs->top--;
            i--;
        }
    }
    if (i != abs(num_lines)) {
        cs->y = 0;
        werase(cs->base.win);
        print_all_connections(cs);
    }
}
