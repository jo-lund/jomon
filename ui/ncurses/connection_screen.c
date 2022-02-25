#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "connection_screen.h"
#include "help_screen.h"
#include "menu.h"
#include "decoder/tcp_analyzer.h"
#include "decoder/packet.h"
#include "decoder/packet_ip.h"
#include "monitor.h"
#include "process.h"
#include "conversation_screen.h"
#include "actionbar.h"

#define ADDR_WIDTH 17
#define PORT_WIDTH 10
#define STATE_WIDTH 14
#define PACKET_WIDTH 9
#define BYTES_WIDTH 14
#define PACKETS_AB_WIDTH 16
#define BYTES_AB_WIDTH 14
#define PROC_WIDTH 20
#define MAX_WIDTH 20
#define CONN_HEADER 5

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
    BYTES_BA,
    PROCESS,
    NUM_VALS
};

enum page {
    CONNECTION_PAGE,
    PROCESS_PAGE,
};

struct cs_entry {
    uint32_t val;
    union {
        char buf[MAX_WIDTH];
        char *str;
    };
};

enum filter_mode {
    GREY_OUT_CLOSED,
    REMOVE_CLOSED,
    SHOW_ALL,
    NUM_MODES
};

extern main_menu *menu;
static bool active = false;
static enum page view;
static enum filter_mode mode;

static void connection_screen_init(screen *s);
static void connection_screen_refresh(screen *s);
static void connection_screen_get_input(screen *s);
static void connection_screen_got_focus(screen *s, screen *oldscr UNUSED);
static void connection_screen_lost_focus();
static unsigned int connection_screen_get_size(screen *s);
static void connection_screen_on_back(screen *s);
static void connection_screen_render(connection_screen *cs);
static void update_connection(struct tcp_connection_v4 *c, bool new_connection);
static void print_all_connections(connection_screen *cs);
static void print_conn_header(connection_screen *cs);

static screen_operations csop = {
    .screen_init = connection_screen_init,
    .screen_free = connection_screen_free,
    .screen_refresh = connection_screen_refresh,
    .screen_get_input = connection_screen_get_input,
    .screen_got_focus = connection_screen_got_focus,
    .screen_lost_focus = connection_screen_lost_focus,
    .screen_get_data_size = connection_screen_get_size,
    .screen_on_back = connection_screen_on_back
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
    { "Bytes A <- B", BYTES_AB_WIDTH },
    { "Local Process", PROC_WIDTH }
};

static screen_header proc_header[] = {
    { "Local Process", 35 },
    { "Pid", 10 },
    { "User", 20 },
    { "Connections", 13 },
    { "Bytes Sent", 12 },
    { "Bytes Received", 12 }
};

static unsigned int header_size;
static unsigned int num_pages;

static void update_screen_buf(screen *s)
{
    vector_clear(((connection_screen *) s)->screen_buf, NULL);
    if (view == CONNECTION_PAGE) {
        hashmap_t *sessions = tcp_analyzer_get_sessions();
        const hashmap_iterator *it;

        HASHMAP_FOREACH(sessions, it)
            vector_push_back(((connection_screen *) s)->screen_buf, it->data);
    } else {
        hashmap_t *procs = process_get_processes();
        const hashmap_iterator *it;

        HASHMAP_FOREACH(procs, it)
            vector_push_back(((connection_screen *) s)->screen_buf, it->data);
    }
}

static void print_process(connection_screen *cs, struct process *proc, int y)
{
    char name[MAXPATH];
    int x = 0;
    const node_t *n, *m;
    struct cs_entry entry[NUM_VALS];
    struct tcp_connection_v4 *conn;
    struct packet *p;
    unsigned int nconn = 0;

    if (!proc->name)
        return;
    strncpy(name, proc->name, MAXPATH - 1);
    mvwprintw(cs->base.win, y, x, "%s", get_file_part(name));
    x += proc_header[0].width;
    mvwprintw(cs->base.win, y, x, "%d", proc->pid);
    x += proc_header[1].width;
    mvwprintw(cs->base.win, y, x, "%s", proc->user);
    x += proc_header[2].width;
    memset(entry, 0, sizeof(entry));
    if (!proc->conn) {
        mvwprintw(cs->base.win, y, x, "0");
        x += proc_header[3].width;
        mvwprintw(cs->base.win, y, x, "0");
        mvwprintw(cs->base.win, y, x + proc_header[4].width, "0");
        return;
    }
    DLIST_FOREACH(proc->conn, n) {
        nconn++;
        conn = list_data(n);
        entry[ADDRA].val = conn->endp->src;
        entry[PORTA].val = conn->endp->sport;
        entry[ADDRB].val = conn->endp->dst;
        entry[PORTB].val = conn->endp->dport;
        DLIST_FOREACH(conn->packets, m) {
            p = list_data(m);
            if (entry[ADDRA].val == ipv4_src(p) && entry[PORTA].val == tcp_member(p, sport)) {
                entry[BYTES_AB].val += p->len;
                entry[PACKETS_AB].val++;
            } else if (entry[ADDRB].val == ipv4_src(p) &&
                       entry[PORTB].val == tcp_member(p, sport)) {
                entry[BYTES_BA].val += p->len;
                entry[PACKETS_BA].val++;
            }
        }
    }
    mvwprintw(cs->base.win, y, x, "%u", nconn);
    x += proc_header[3].width;
    format_bytes(entry[BYTES_AB].val, entry[BYTES_AB].buf, MAX_WIDTH);
    format_bytes(entry[BYTES_BA].val, entry[BYTES_BA].buf, MAX_WIDTH);
    mvwprintw(cs->base.win, y, x, "%s", entry[BYTES_AB].buf);
    x += proc_header[4].width;
    mvwprintw(cs->base.win, y, x, "%s", entry[BYTES_BA].buf);
}

static void print_connection(connection_screen *cs, struct tcp_connection_v4 *conn, int y)
{
    const node_t *n = list_begin(conn->packets);
    struct packet *p;
    char *state;
    int x = 0;
    struct cs_entry entry[NUM_VALS];
    int attrs = 0;

    memset(entry, 0, sizeof(entry));
    inet_ntop(AF_INET, &conn->endp->src, entry[ADDRA].buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &conn->endp->dst, entry[ADDRB].buf, INET_ADDRSTRLEN);
    p = list_data(n);
    entry[ADDRA].val = conn->endp->src;
    entry[PORTA].val = conn->endp->sport;
    entry[ADDRB].val = conn->endp->dst;
    entry[PORTB].val = conn->endp->dport;
    while (n) {
        p = list_data(n);
        if (entry[ADDRA].val == ipv4_src(p) && entry[PORTA].val == tcp_member(p, sport)) {
            entry[BYTES_AB].val += p->len;
            entry[PACKETS_AB].val++;
        } else if (entry[ADDRB].val == ipv4_src(p) &&
                   entry[PORTB].val == tcp_member(p, sport)) {
            entry[BYTES_BA].val += p->len;
            entry[PACKETS_BA].val++;
        }
        entry[BYTES].val += p->len;
        n = list_next(n);
    }
    state = tcp_analyzer_get_connection_state(conn->state);
    strncpy(entry[STATE].buf, state, MAX_WIDTH - 1);
    entry[PACKETS].val = list_size(conn->packets);
    format_bytes(entry[BYTES].val, entry[BYTES].buf, MAX_WIDTH);
    format_bytes(entry[BYTES_AB].val, entry[BYTES_AB].buf, MAX_WIDTH);
    format_bytes(entry[BYTES_BA].val, entry[BYTES_BA].buf, MAX_WIDTH);
    if (!ctx.opt.load_file)
        entry[PROCESS].str = process_get_name(conn);
    if (mode == GREY_OUT_CLOSED && (conn->state == CLOSED || conn->state == RESET))
        attrs = get_theme_colour(DISABLE);
    for (unsigned int i = 0; i < header_size; i++) {
        if (i % 2 == 0) {
            printat(cs->base.win, y, x, attrs, "%s", entry[i].buf);
        } else {
            if (i == PROCESS) {
                if (entry[i].str)
                    printat(cs->base.win, y, x, attrs, "%s", entry[i].str);
            } else
                printat(cs->base.win, y, x, attrs, "%d", entry[i].val);
        }
        x += header[i].width;
    }
}

static void update_header(void)
{
    if (ctx.opt.load_file) {
        header_size = ARRAY_SIZE(header) - 1;
        num_pages = 1;
        view = CONNECTION_PAGE;
    } else {
        header_size = ARRAY_SIZE(header);
        num_pages = 2;
    }
}

connection_screen *connection_screen_create(void)
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

    screen_init(s);
    getmaxyx(stdscr, my, mx);
    s->win = newwin(my - CONN_HEADER - actionbar_getmaxy(actionbar), mx, CONN_HEADER, 0);
    s->have_selectionbar = true;
    s->lines = getmaxy(stdscr) - CONN_HEADER - actionbar_getmaxy(actionbar);
    view = CONNECTION_PAGE;
    cs->header = newwin(CONN_HEADER, mx, 0, 0);
    cs->y = 0;
    cs->screen_buf = vector_init(1024);
    mode = GREY_OUT_CLOSED;
    scrollok(s->win, TRUE);
    nodelay(s->win, TRUE);
    keypad(s->win, TRUE);
}

void connection_screen_free(screen *s)
{
    connection_screen *cs = (connection_screen *) s;

    delwin(cs->header);
    delwin(s->win);
    vector_free(cs->screen_buf, NULL);
    free(cs);
}

void connection_screen_got_focus(screen *s, screen *oldscr UNUSED)
{
    if (!active) {
        s->top = 0;
        update_header();
        update_screen_buf(s);
        tcp_analyzer_subscribe(update_connection);
        active = true;
    }
    if (ctx.capturing)
        alarm(1);
}

void connection_screen_lost_focus()
{
    if (ctx.capturing)
        alarm(0);
}

void connection_screen_on_back(screen *s)
{
    tcp_analyzer_unsubscribe(update_connection);
    vector_clear(((connection_screen *) s)->screen_buf, NULL);
    active = false;
}

void connection_screen_refresh(screen *s)
{
    connection_screen *cs = (connection_screen *) s;

    werase(s->win);
    werase(cs->header);
    cs->y = 0;
    wbkgd(s->win, get_theme_colour(BACKGROUND));
    wbkgd(cs->header, get_theme_colour(BACKGROUND));
    connection_screen_render(cs);
}

void connection_screen_get_input(screen *s)
{
    int c = wgetch(s->win);
    connection_screen *cs = (connection_screen *) s;
    conversation_screen *cvs;

    switch (c) {
    case KEY_ENTER:
    case '\n':
        cvs = (conversation_screen *) screen_cache_get(CONVERSATION_SCREEN);
        cvs->stream = vector_get(cs->screen_buf, s->selectionbar);
        screen_stack_move_to_top((screen *) cvs);
        break;
    case 'f':
        s->top = 0;
        mode = (mode + 1) % NUM_MODES;
        connection_screen_refresh(s);
        break;
    case 'p':
        if (view == CONNECTION_PAGE && s->show_selectionbar)
            s->show_selectionbar = false;
        view = (view + 1) % num_pages;
        update_screen_buf(s);
        if (num_pages > 1)
            s->top = 0;
        connection_screen_refresh(s);
        break;
    default:
        s->have_selectionbar = (view == CONNECTION_PAGE);
        ungetch(c);
        screen_get_input(s);
        break;
    }
}

static unsigned int connection_screen_get_size(screen *s)
{
    if (mode == REMOVE_CLOSED) {
        connection_screen *cs = (connection_screen *) s;
        unsigned int c = 0;
        struct tcp_connection_v4 *conn;

        for (int i = 0; i < vector_size(cs->screen_buf); i++) {
            conn = vector_get(cs->screen_buf, i);
            if (conn->state != CLOSED && conn->state != RESET)
                c++;
        }
        return c;
    } else {
        return vector_size(((connection_screen *) s)->screen_buf);
    }
}

void connection_screen_render(connection_screen *cs)
{
    touchwin(cs->header);
    touchwin(cs->base.win);
    print_conn_header(cs);
    print_all_connections(cs);
    actionbar_refresh(actionbar, (screen *) cs);
}

void update_connection(struct tcp_connection_v4 *conn, bool new_connection)
{
    connection_screen *cs = (connection_screen *) screen_cache_get(CONNECTION_SCREEN);

    if (!new_connection)
        return;
    if (view == PROCESS_PAGE) {
        if (cs->base.focus) {
            update_screen_buf((screen *) cs);
            actionbar_refresh(actionbar, (screen *) cs);
        }
    } else {
        vector_push_back(cs->screen_buf, conn);
        if (cs->base.focus) {
            werase(cs->header);
            print_conn_header(cs);
            actionbar_refresh(actionbar, (screen *) cs);
        }
    }
}

void print_conn_header(connection_screen *cs)
{
    int y = 0;
    int x = 0;
    screen_header *p;
    unsigned int size;

    if (view == CONNECTION_PAGE) {
        p = header;
        size = header_size;
        printat(cs->header, y, 0, get_theme_colour(HEADER_TXT), "TCP connections");
        wprintw(cs->header,  ": %d", connection_screen_get_size((screen *) cs));
        printat(cs->header, ++y, 0, get_theme_colour(HEADER_TXT), "View");
        switch (mode) {
        case GREY_OUT_CLOSED:
            wprintw(cs->header,  ": Normal");
            break;
        case REMOVE_CLOSED:
            wprintw(cs->header,  ": Active");
            break;
        case SHOW_ALL:
            wprintw(cs->header,  ": All");
            break;
        default:
            break;
        }
        y += 3;
    } else {
        p = proc_header;
        size = ARRAY_SIZE(proc_header);
        printat(cs->header, y, 0, get_theme_colour(HEADER_TXT), "Processes");
        wprintw(cs->header,  ": %d", vector_size(cs->screen_buf));
        y += 4;
    }
    for (unsigned int i = 0; i < size; i++, p++) {
        mvwprintw(cs->header, y, x, "%s", p->txt);
        x += p->width;
    }
    mvwchgat(cs->header, y, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
    wrefresh(cs->header);
}

void print_all_connections(connection_screen *cs)
{
    int i = cs->base.top;

    while (cs->y < cs->base.lines && i < vector_size(cs->screen_buf)) {
        if (view == CONNECTION_PAGE) {
            struct tcp_connection_v4 *conn;

            conn = vector_get(cs->screen_buf, i);
            if (mode == REMOVE_CLOSED && (conn->state == CLOSED || conn->state == RESET)) {
                i++;
                continue;
            }
            print_connection(cs, conn, cs->y);
        } else {
            print_process(cs, vector_get(cs->screen_buf, i), cs->y);
        }
        cs->y++;
        i++;
    }
    if (cs->base.selectionbar >= vector_size(cs->screen_buf))
        cs->base.selectionbar = vector_size(cs->screen_buf) - 1;
    if (cs->base.show_selectionbar)
        mvwchgat(cs->base.win, cs->base.selectionbar - cs->base.top, 0, -1, A_NORMAL,
                 PAIR_NUMBER(get_theme_colour(SELECTIONBAR)), NULL);
    wrefresh(cs->base.win);
}
