#define CONN_WIDTH 46
#define CONN_HEADER 3
#define STATUS_HEIGHT 1

#include <stdlib.h>
#include <arpa/inet.h>
#include "connection_screen.h"
#include "help_screen.h"
#include "../decoder/tcp_analyzer.h"
#include "../misc.h"

extern WINDOW *status;

static void connection_screen_init(screen *s);
static void connection_screen_refresh(screen *s);
static void connection_screen_get_input(screen *s);
static void connection_screen_got_focus();
static void connection_screen_lost_focus();
static void render_screen(connection_screen *cs);
static void update_connection(void *data);
static void print_connections(connection_screen *cs);
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
    cs->top = 0;;
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

void connection_screen_got_focus()
{
    analyzer_subscribe(update_connection);
}

void connection_screen_lost_focus()
{
    analyzer_unsubscribe(update_connection);
}

void connection_screen_refresh(screen *s)
{
    render_screen((connection_screen *) s);
}

void connection_screen_get_input(screen *s)
{
    int c = wgetch(s->win);
    connection_screen *cs = (connection_screen *) s;

    switch (c) {
    case 'x':
    case KEY_ESC:
    case KEY_F(3):
        pop_screen();
        break;
    case KEY_F(1):
    {
        screen *scr;

        if (!(scr = screen_cache_get(HELP_SCREEN))) {
            scr = help_screen_create();
            screen_cache_insert(HELP_SCREEN, scr);
        }
        push_screen(scr);
        break;
    }
    // TODO: Handle scrolling
    case KEY_UP:
        break;
    case KEY_DOWN:
    {
        struct tcp_connection_v4 *data = list_back(cs->screen_buf);
        const hash_map_iterator *it = hash_map_get_it(cs->sessions, data->endp);

        it = hash_map_next(cs->sessions, it);
        if (it) {

        }
        break;
    }
    default:
        break;
    }
}

void render_screen(connection_screen *cs)
{
    int y = 0;

    touchwin(cs->header);
    touchwin(cs->base.win);
    print_conn_header(cs);
    if (hash_map_size(cs->sessions)) {
        const hash_map_iterator *it = hash_map_first(cs->sessions);

        while (it) {
            if (y < cs->lines) {
                list_push_back(cs->screen_buf, it->data);
            } else {
                break;
            }
            y++;
            it = hash_map_next(cs->sessions, it);
        }
    }
    cs->y = y + 1;
    print_connections(cs);
    print_status();
}

void update_connection(void *data)
{
    struct tcp_connection_v4 *conn = (struct tcp_connection_v4 *) data;
    bool found = false;
    connection_screen *cs = (connection_screen *) screen_cache_get(CONNECTION_SCREEN);

    werase(cs->base.win); // TODO: Use wclrtoeol instead of erasing the entire screen
    print_conn_header(cs);
    if (list_size(cs->screen_buf) < cs->lines) {
        const node_t *n = list_begin(cs->screen_buf);

        while (n) {
            if (list_data(n) == conn) {
                found = true;
                break;
            }
            n = list_next(n);
        }
        if (!found) {
            list_push_back(cs->screen_buf, conn);
        }
    }
    print_connections(cs);
}

void print_conn_header(connection_screen *cs)
{
    int y = 0;

    printat(cs->header, y, 0, get_theme_colour(HEADER_TXT), "TCP sessions");
    wprintw(cs->header,  ": %d", hash_map_size(cs->sessions));
    y += 2;
    mvwprintw(cs->header, y, 0, "Connection");
    mvwprintw(cs->header, y, CONN_WIDTH, "State");
    mvwchgat(cs->header, y, 0, -1, A_STANDOUT, 0, NULL);
    wrefresh(cs->header);
}

void print_connections(connection_screen *cs)
{
    int y = 0;
    const node_t *n = list_begin(cs->screen_buf);

    while (n) {
        char buf[MAXLINE];
        char srcaddr[INET_ADDRSTRLEN];
        char dstaddr[INET_ADDRSTRLEN];
        struct tcp_connection_v4 *conn = list_data(n);

        inet_ntop(AF_INET, &conn->endp->src, srcaddr, sizeof(srcaddr));
        inet_ntop(AF_INET, &conn->endp->dst, dstaddr, sizeof(dstaddr));
        snprintf(buf, MAXLINE, "%s:%d <=> %s:%d", srcaddr, conn->endp->src_port,
                 dstaddr, conn->endp->dst_port);
        mvwprintw(cs->base.win, y, 0, "%s", buf);
        mvwprintw(cs->base.win, y++, CONN_WIDTH, "%s",
                  analyzer_get_connection_state(conn->state));
        n = list_next(n);
    }
    wrefresh(cs->base.win);
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
