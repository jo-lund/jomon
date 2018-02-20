#define CONN_WIDTH 46
#define STATE_WIDTH 14
#define PACKET_WIDTH 8
#define CONN_HEADER 3
#define STATUS_HEIGHT 1

#include <stdlib.h>
#include <arpa/inet.h>
#include "connection_screen.h"
#include "help_screen.h"
#include "menu.h"
#include "../decoder/tcp_analyzer.h"
#include "../decoder/packet.h"
#include "../misc.h"
#include "../util.h"

extern WINDOW *status;
extern main_menu *menu;

static void connection_screen_init(screen *s);
static void connection_screen_refresh(screen *s);
static void connection_screen_get_input(screen *s);
static void connection_screen_got_focus(screen *s __attribute__((unused)));
static void connection_screen_lost_focus(screen *s __attribute__((unused)));
static void connection_screen_render(connection_screen *cs);
static void update_connection(void *data);
static void print_all_connections(connection_screen *cs);
static void print_connection(connection_screen *cs, struct tcp_connection_v4 *conn, int y);
static void print_conn_header(connection_screen *cs);
static void print_status();

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
    cs->y = 0;
    cs->lines = my - CONN_HEADER - STATUS_HEIGHT;
    cs->screen_buf = list_init();
    cs->sessions = analyzer_get_sessions();
    scrollok(cs->base.win, TRUE);
    nodelay(cs->base.win, TRUE);
    keypad(cs->base.win, TRUE);
}

void connection_screen_free(screen *s)
{
    connection_screen *cs = (connection_screen *) s;

    delwin(cs->header);
    delwin(s->win);
    list_free(cs->screen_buf, NULL);
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
    list_clear(cs->screen_buf, NULL);
    cs->y = 0;
    wbkgd(s->win, get_theme_colour(BACKGROUND));
    wbkgd(cs->header, get_theme_colour(BACKGROUND));
    connection_screen_render(cs);
}

void connection_screen_get_input(screen *s)
{
    connection_screen *cs = (connection_screen *) s;
    int c = wgetch(cs->base.win);

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
    {
        struct tcp_connection_v4 *data = list_front(cs->screen_buf);
        const hash_map_iterator *it = hash_map_get_it(cs->sessions, data->endp);

        it = hash_map_prev(cs->sessions, it);
        if (it) {
            list_push_front(cs->screen_buf, it->data);
            list_pop_back(cs->screen_buf, NULL);
            wscrl(cs->base.win, -1);
            print_connection(cs, it->data, 0);
            wrefresh(cs->base.win);
        }
        break;
    }
    case KEY_DOWN:
    {
        struct tcp_connection_v4 *data = list_back(cs->screen_buf);
        const hash_map_iterator *it = hash_map_get_it(cs->sessions, data->endp);

        it = hash_map_next(cs->sessions, it);
        if (it) {
            list_pop_front(cs->screen_buf, NULL);
            list_push_back(cs->screen_buf, it->data);
            wscrl(cs->base.win, 1);
            print_connection(cs, it->data, cs->y - 1);
            wrefresh(cs->base.win);
        }
        break;
    }
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
    touchwin(cs->header);
    touchwin(cs->base.win);
    print_conn_header(cs);
    if (hash_map_size(cs->sessions)) {
        const hash_map_iterator *it = hash_map_first(cs->sessions);

        while (it) {
            if (cs->y < cs->lines) {
                list_push_back(cs->screen_buf, it->data);
                cs->y++;
            } else {
                break;
            }
            it = hash_map_next(cs->sessions, it);
        }
    }
    print_all_connections(cs);
    print_status();
}

void update_connection(void *data)
{
    struct tcp_connection_v4 *conn = (struct tcp_connection_v4 *) data;
    bool found = false;
    connection_screen *cs = (connection_screen *) screen_cache_get(CONNECTION_SCREEN);
    int y = 0;
    const node_t *n = list_begin(cs->screen_buf);

    werase(cs->header);
    print_conn_header(cs);
    while (n) {
        if (list_data(n) == conn) {
            found = true;
            break;
        }
        n = list_next(n);
        y++;
    }
    if (list_size(cs->screen_buf) < cs->lines && !found) {
        list_push_back(cs->screen_buf, conn);
        print_connection(cs, conn, cs->y);
        cs->y++;
        wrefresh(cs->base.win);
    } else if (found) {
        wmove(cs->base.win, y, 0);
        wclrtoeol(cs->base.win);
        print_connection(cs, conn, y);
        wrefresh(cs->base.win);
    }
}

void print_conn_header(connection_screen *cs)
{
    int y = 0;

    printat(cs->header, y, 0, get_theme_colour(HEADER_TXT), "TCP sessions");
    wprintw(cs->header,  ": %d", hash_map_size(cs->sessions));
    y += 2;
    mvwprintw(cs->header, y, 0, "Connection");
    mvwprintw(cs->header, y, CONN_WIDTH, "State");
    mvwprintw(cs->header, y, CONN_WIDTH + STATE_WIDTH, "Packets");
    mvwprintw(cs->header, y, CONN_WIDTH + STATE_WIDTH + PACKET_WIDTH, "Bytes");
    mvwchgat(cs->header, y, 0, -1, A_STANDOUT, 0, NULL);
    wrefresh(cs->header);
}

void print_all_connections(connection_screen *cs)
{
    int y = 0;
    const node_t *n = list_begin(cs->screen_buf);

    while (n) {
        print_connection(cs, list_data(n), y);
        y++;
        n = list_next(n);
    }
    wrefresh(cs->base.win);
}

void print_connection(connection_screen *cs, struct tcp_connection_v4 *conn, int y)
{
    char buf[MAXLINE];
    char srcaddr[INET_ADDRSTRLEN];
    char dstaddr[INET_ADDRSTRLEN];
    uint32_t bytes = 0;
    const node_t *n = list_begin(conn->packets);

    inet_ntop(AF_INET, &conn->endp->src, srcaddr, sizeof(srcaddr));
    inet_ntop(AF_INET, &conn->endp->dst, dstaddr, sizeof(dstaddr));
    snprintf(buf, MAXLINE, "%s:%d <=> %s:%d", srcaddr, conn->endp->src_port,
             dstaddr, conn->endp->dst_port);
    while (n) {
        struct packet *p = list_data(n);

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
    } else {
        mvwprintw(cs->base.win, y, 0, "%s", buf);
        mvwprintw(cs->base.win, y, CONN_WIDTH, "%s",
                  analyzer_get_connection_state(conn->state));
        mvwprintw(cs->base.win, y, CONN_WIDTH + STATE_WIDTH, "%d",
                  list_size(conn->packets));
        mvwprintw(cs->base.win, y, CONN_WIDTH + STATE_WIDTH + PACKET_WIDTH, "%s",
                  format_bytes(bytes, buf, MAXLINE));
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
