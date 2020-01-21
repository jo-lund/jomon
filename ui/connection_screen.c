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
#include "../attributes.h"

#define ADDR_WIDTH 17
#define PORT_WIDTH 10
#define STATE_WIDTH 14
#define PACKET_WIDTH 9
#define BYTES_WIDTH 14
#define PACKETS_AB_WIDTH 16
#define BYTES_AB_WIDTH 14
#define MAX_WIDTH 20
#define CONN_HEADER 3
#define STATUS_HEIGHT 1

enum cs_val {
    ADDRA,
    PORTA,
    ADDRB,
    PORTB,
    STATE,
    PACKETS,
    BYTES,
    PACKETS_AB,
    BYTES_AB,
    PACKETS_BA,
    BYTES_BA
};

struct cs_entry {
    uint32_t val;
    char buf[MAX_WIDTH];
};

extern WINDOW *status;
extern main_menu *menu;

static void connection_screen_init(screen *s);
static void connection_screen_refresh(screen *s);
static void connection_screen_get_input(screen *s);
static void connection_screen_got_focus(screen *s UNUSED);
static void connection_screen_lost_focus(screen *s UNUSED);
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

static screen_header header[] = {
    { "IP Address A", ADDR_WIDTH },
    { "Port A", PORT_WIDTH },
    { "IP Address B", ADDR_WIDTH },
    { "Port B", PORT_WIDTH },
    { "State", STATE_WIDTH },
    { "Packets", PACKET_WIDTH },
    { "Bytes", BYTES_WIDTH },
    { "Packets A -> B", PACKETS_AB_WIDTH },
    { "Bytes A -> B", BYTES_AB_WIDTH },
    { "Packets A <- B", PACKETS_AB_WIDTH },
    { "Bytes A <- B", BYTES_AB_WIDTH }
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

void connection_screen_got_focus(screen *s UNUSED)
{
    tcp_analyzer_subscribe(update_connection);
}

void connection_screen_lost_focus(screen *s UNUSED)
{
    tcp_analyzer_unsubscribe(update_connection);
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
    case 'h':
        screen_stack_move_to_top(screen_cache_get(HOST_SCREEN));
        break;
    case 's':
        screen_stack_move_to_top(screen_cache_get(STAT_SCREEN));
        break;
    case 'q':
    case KEY_F(10):
        finish(0);
        break;
    default:
        break;
    }
}

void connection_screen_render(connection_screen *cs)
{
    hashmap_t *sessions = tcp_analyzer_get_sessions();

    if (hashmap_size(sessions)) {
        const hashmap_iterator *it = hashmap_first(sessions);

        while (it) {
            vector_push_back(cs->screen_buf, it->data);
            it = hashmap_next(sessions, it);
        }
    }
    touchwin(cs->header);
    touchwin(cs->base.win);
    print_conn_header(cs);
    print_all_connections(cs);
    print_status();
}

void update_connection(struct tcp_connection_v4 *conn, bool new_connection)
{
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
    int x = 0;

    printat(cs->header, y, 0, get_theme_colour(HEADER_TXT), "TCP connections");
    wprintw(cs->header,  ": %d", vector_size(cs->screen_buf));
    y += 2;
    for (unsigned int i = 0; i < sizeof(header) / sizeof(header[0]); i++) {
        mvwprintw(cs->header, y, x, header[i].txt);
        x += header[i].width;
    }
    mvwchgat(cs->header, y, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
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
    const node_t *n = list_begin(conn->packets);
    struct packet *p;
    char *state;
    int x = 0;
    struct cs_entry entry[11];

    memset(entry, 0, sizeof(entry));
    inet_ntop(AF_INET, &conn->endp->src, entry[ADDRA].buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &conn->endp->dst, entry[ADDRB].buf, INET_ADDRSTRLEN);
    p = list_data(n);
    entry[ADDRA].val = conn->endp->src;
    entry[PORTA].val = conn->endp->src_port;
    entry[ADDRB].val = conn->endp->dst;
    entry[PORTB].val = conn->endp->dst_port;
    while (n) {
        p = list_data(n);
        if (entry[ADDRA].val == ipv4_src(p) && entry[PORTA].val == get_tcp_src(p)) {
            entry[BYTES_AB].val += p->len;
            entry[PACKETS_AB].val++;
        } else if (entry[ADDRB].val == ipv4_src(p) &&
                   entry[PORTB].val == get_tcp_src(p)) {
            entry[BYTES_BA].val += p->len;
            entry[PACKETS_BA].val++;
        }
        entry[BYTES].val += p->len;
        n = list_next(n);
    }
    state = tcp_analyzer_get_connection_state(conn->state);
    strncpy(entry[STATE].buf, state, MAX_WIDTH);
    entry[PACKETS].val = list_size(conn->packets);
    format_bytes(entry[BYTES].val, entry[BYTES].buf, MAX_WIDTH);
    format_bytes(entry[BYTES_AB].val, entry[BYTES_AB].buf, MAX_WIDTH);
    format_bytes(entry[BYTES_BA].val, entry[BYTES_BA].buf, MAX_WIDTH);
    if (conn->state != ESTABLISHED && conn->state != SYN_SENT &&
        conn->state != SYN_RCVD) {
        for (unsigned int i = 0; i < ARRAY_SIZE(header); i++) {
            if (i % 2 == 0) {
                printat(cs->base.win, y, x, get_theme_colour(DISABLE), "%s", entry[i].buf);
            } else {
                printat(cs->base.win, y, x, get_theme_colour(DISABLE), "%d", entry[i].val);
            }
            x += header[i].width;
        }
    } else {
        for (unsigned int i = 0; i < ARRAY_SIZE(header); i++) {
            if (i % 2 == 0) {
                mvwprintw(cs->base.win, y, x, "%s", entry[i].buf);
            } else {
                mvwprintw(cs->base.win, y, x, "%d", entry[i].val);
            }
            x += header[i].width;
        }
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
