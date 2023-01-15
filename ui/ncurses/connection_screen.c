#define _GNU_SOURCE
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
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
#include "signal.h"

#define ADDR_WIDTH 17
#define PORT_WIDTH 10
#define STATE_WIDTH 14
#define PACKET_WIDTH 10
#define BYTES_WIDTH 14
#define PACKETS_AB_WIDTH 17
#define BYTES_AB_WIDTH 15
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

static void connection_screen_init(screen *s);
static void connection_screen_refresh(screen *s);
static void connection_screen_get_input(screen *s);
static void connection_screen_got_focus(screen *s, screen *oldscr UNUSED);
static void connection_screen_lost_focus();
static unsigned int connection_screen_get_size(screen *s);
static void connection_screen_on_back(screen *s);
static void connection_screen_render(connection_screen *cs);

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

static screen_header conn_header[] = {
    { "IP Address A", ADDR_WIDTH, -1 },
    { "Port A", PORT_WIDTH, -1 },
    { "IP Address B", ADDR_WIDTH, -1 },
    { "Port B", PORT_WIDTH, -1 },
    { "State", STATE_WIDTH, -1 },
    { "Packets", PACKET_WIDTH, -1 },
    { "Bytes", BYTES_WIDTH, -1 },
    { "Packets A -> B", PACKETS_AB_WIDTH, -1 },
    { "Bytes A -> B", BYTES_AB_WIDTH, -1 },
    { "Packets A <- B", PACKETS_AB_WIDTH, -1 },
    { "Bytes A <- B", BYTES_AB_WIDTH, -1 },
    { "Local Process", PROC_WIDTH, -1 }
};

static screen_header proc_header[] = {
    { "Local Process", 35, -1 },
    { "Pid", 10, -1 },
    { "User", 20, -1 },
    { "Connections", 14, -1 },
    { "Bytes Sent", 13, -1 },
    { "Bytes Received", 17, -1}
};

extern main_menu *menu;
static bool active = false;
static enum page view;
static enum filter_mode mode;
static bool tab_active = false;
static unsigned int conn_header_size;
static hashmap_t *connection_data = NULL;

static int get_active_header_focus(screen_header *hdr, int size)
{
    for (int i = 0; i < size; i++)
        if (hdr[i].order != -1)
            return i;
    return -1;
}

static int calculate_data(struct tcp_connection_v4 *conn, int d)
{
    uint32_t *entry;

    if ((entry = hashmap_get(connection_data, conn)) == NULL) {
        struct packet *p;
        const node_t *n = list_begin(conn->packets);

        entry = calloc(NUM_VALS, sizeof(*entry));
        entry[ADDRA] = conn->endp->src;
        entry[PORTA] = conn->endp->sport;
        entry[ADDRB] = conn->endp->dst;
        entry[PORTB] = conn->endp->dport;
        while (n) {
            p = list_data(n);
            if (entry[ADDRA] == ipv4_src(p) && entry[PORTA] == tcp_member(p, sport)) {
                entry[BYTES_AB] += p->len;
                entry[PACKETS_AB]++;
            } else if (entry[ADDRB] == ipv4_src(p) &&
                       entry[PORTB] == tcp_member(p, sport)) {
                entry[BYTES_BA] += p->len;
                entry[PACKETS_BA]++;
            }
            entry[BYTES] += p->len;
            n = list_next(n);
        }
        hashmap_insert(connection_data, conn, entry);
    }
    switch (d) {
    case BYTES:
        return entry[BYTES];
    case PACKETS_AB:
        return entry[PACKETS_AB];
    case BYTES_AB:
        return entry[BYTES_AB];
    case PACKETS_BA:
        return entry[PACKETS_BA];
    case BYTES_BA:
        return entry[BYTES_BA];
    default:
        return 0;
    }
}

static int calculate_proc(struct process *proc, int d)
{
    uint32_t entry[NUM_VALS];
    struct packet *p;
    uint32_t nconn = 0;
    const node_t *n, *m;
    struct tcp_connection_v4 *conn;

    memset(entry, 0, sizeof(entry));
    DLIST_FOREACH(proc->conn, n) {
        nconn++;
        if (d == 3)
            continue;
        conn = list_data(n);
        entry[ADDRA] = conn->endp->src;
        entry[PORTA] = conn->endp->sport;
        entry[ADDRB] = conn->endp->dst;
        entry[PORTB] = conn->endp->dport;
        DLIST_FOREACH(conn->packets, m) {
            p = list_data(m);
            if (entry[ADDRA] == ipv4_src(p) && entry[PORTA] == tcp_member(p, sport)) {
                entry[BYTES_AB] += p->len;
            } else if (entry[ADDRB] == ipv4_src(p) &&
                       entry[PORTB] == tcp_member(p, sport)) {
                entry[BYTES_BA] += p->len;
            }
        }
    }
    switch (d) {
    case 3:
        return nconn;
    case 4:
        return entry[BYTES_AB];
    case 5:
        return entry[BYTES_BA];
    default:
        return 0;
    }
}

static int cmp_proc(const void *d1, const void *d2, void *arg)
{
    struct process *p1 = *(struct process **) d1;
    struct process *p2 = *(struct process **) d2;
    int pos = PTR_TO_INT(arg);

    switch (pos) {
    case 0:
        return (proc_header[pos].order == HDR_INCREASING) ?
            strcmp(p1->name, p2->name) : strcmp(p2->name, p1->name);
    case 1:
        return (proc_header[pos].order == HDR_INCREASING) ?
            p1->pid - p2->pid : p2->pid - p1->pid;
    case 2:
        return (proc_header[pos].order == HDR_INCREASING) ?
            strcmp(p1->user, p2->user) : strcmp(p2->user, p1->user);
    case 3:
    case 4:
    case 5:
        return (proc_header[pos].order == HDR_INCREASING) ?
            calculate_proc(p1, pos) - calculate_proc(p2, pos)
            : calculate_proc(p2, pos) - calculate_proc(p1, pos);
    default:
        return 0;
    }
}

static int cmp_conn(const void *p1, const void *p2, void *arg)
{
    struct tcp_connection_v4 *c1 = *(struct tcp_connection_v4 **) p1;
    struct tcp_connection_v4 *c2 = *(struct tcp_connection_v4 **) p2;
    int pos = PTR_TO_INT(arg);
    int64_t res;

    switch (pos) {
    case ADDRA:
        if (conn_header[pos].order == HDR_INCREASING)
            res = (int64_t) ntohl(c1->endp->src) - (int64_t) ntohl(c2->endp->src);
        else
            res = (int64_t) ntohl(c2->endp->src) - (int64_t) ntohl(c1->endp->src);
        return (res < 0) ? -1 : (res > 0) ? 1 : 0;
    case PORTA:
        return (conn_header[pos].order == HDR_INCREASING) ? c1->endp->sport - c2->endp->sport
            : c2->endp->sport - c1->endp->sport;
    case ADDRB:
        if (conn_header[pos].order == HDR_INCREASING)
            res = (int64_t) ntohl(c1->endp->dst) - (int64_t) ntohl(c2->endp->dst);
        else
            res = (int64_t) ntohl(c2->endp->dst) - (int64_t) ntohl(c1->endp->dst);
        return (res < 0) ? -1 : (res > 0) ? 1 : 0;
    case PORTB:
        return (conn_header[pos].order == HDR_INCREASING) ? c1->endp->dport - c2->endp->dport
            : c2->endp->dport - c1->endp->dport;
    case STATE:
        return (conn_header[pos].order == HDR_INCREASING) ? c1->state - c2->state
            : c2->state - c1->state;
    case PACKETS:
        return (conn_header[pos].order == HDR_INCREASING) ?
            list_size(c1->packets) - list_size(c2->packets)
            : list_size(c2->packets) - list_size(c1->packets);
    case BYTES:
    case PACKETS_AB:
    case BYTES_AB:
    case PACKETS_BA:
    case BYTES_BA:
        return (conn_header[pos].order == HDR_INCREASING) ?
            calculate_data(c1, pos) - calculate_data(c2, pos)
            : calculate_data(c2, pos) - calculate_data(c1, pos);
    case PROCESS:
    {
        char *s1 = process_get_name(c1);
        char *s2 = process_get_name(c2);

        if (s1 == NULL)
            s1 = "";
        if (s2 == NULL)
            s2 = "";
        return (conn_header[pos].order == HDR_INCREASING) ? strcmp(s1, s2) : strcmp(s2, s1);
    }
    default:
        return 0;
    }
}

static void update_screen_buf(screen *s)
{
    connection_screen *cs;

    cs = (connection_screen *) s;
    vector_clear(cs->screen_buf, NULL);
    if (view == CONNECTION_PAGE) {
        hashmap_t *sessions = tcp_analyzer_get_sessions();
        const hashmap_iterator *it;
        struct tcp_connection_v4 *conn;

        HASHMAP_FOREACH(sessions, it) {
            conn = it->data;
            if (mode == REMOVE_CLOSED) {
                if (conn->state != CLOSED && conn->state != RESET)
                    vector_push_back(cs->screen_buf, conn);
            } else {
                vector_push_back(cs->screen_buf, conn);
            }
        }
    } else {
        hashmap_t *procs = process_get_processes();
        const hashmap_iterator *it;

        HASHMAP_FOREACH(procs, it)
            vector_push_back(cs->screen_buf, it->data);
    }
}

static void update_data(void)
{
    connection_screen *cs = (connection_screen *) screen_cache_get(CONNECTION_SCREEN);

    hashmap_clear(connection_data);
    update_screen_buf((screen *) cs);
}

static void handle_alarm(void)
{
    screen *s = (screen *) screen_cache_get(CONNECTION_SCREEN);

    if (s->focus && ctx.capturing) {
        connection_screen *cs = (connection_screen *) s;

        update_screen_buf(s);
        if (view == CONNECTION_PAGE)
            qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
                    sizeof(struct tcp_connection_v4 *), cmp_conn,
                    INT_TO_PTR(get_active_header_focus(conn_header, conn_header_size)));
        else
            qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
                    sizeof(struct process *), cmp_proc,
                    INT_TO_PTR(get_active_header_focus(proc_header, ARRAY_SIZE(proc_header))));
        connection_screen_refresh(s);
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
    uint32_t *val;

    memset(entry, 0, sizeof(entry));
    inet_ntop(AF_INET, &conn->endp->src, entry[ADDRA].buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &conn->endp->dst, entry[ADDRB].buf, INET_ADDRSTRLEN);
    entry[ADDRA].val = conn->endp->src;
    entry[PORTA].val = conn->endp->sport;
    entry[ADDRB].val = conn->endp->dst;
    entry[PORTB].val = conn->endp->dport;
    if ((val = hashmap_get(connection_data, conn))) {
        for (int i = BYTES; i < PROCESS; i++)
            entry[i].val = val[i];
    } else {
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
    for (unsigned int i = 0; i < conn_header_size; i++) {
        if (i % 2 == 0) {
            mvprintat(cs->base.win, y, x, attrs, "%s", entry[i].buf);
        } else {
            if (i == PROCESS) {
                if (entry[i].str) {
                    wattron(cs->base.win, attrs);
                    mvprintnlw(cs->base.win, y, x, 0, "%s", entry[i].str);
                    wattroff(cs->base.win, attrs);
                }
            } else
                mvprintat(cs->base.win, y, x, attrs, "%d", entry[i].val);
        }
        x += conn_header[i].width;
    }
}

static void handle_header_focus(screen *s, int key)
{
    int x = 0;
    int i = 0;
    connection_screen *cs;
    unsigned int size;
    screen_header *p;

    cs = (connection_screen *) s;
    if (view == CONNECTION_PAGE) {
        size = conn_header_size;
        p = conn_header;
    } else {
        size = ARRAY_SIZE(proc_header);
        p = proc_header;
    }
    switch (key) {
    case KEY_RIGHT:
        cs->hpos = (cs->hpos + 1) % size;
        break;
    case KEY_LEFT:
        if (cs->hpos == 0)
            cs->hpos = size - 1;
        else
            cs->hpos = (cs->hpos - 1) % size;
        break;
    default:
        break;
    }
    mvwchgat(cs->header, 4, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
    while (i < cs->hpos)
        x += p[i++].width;
    mvwchgat(cs->header, 4, x, p[i].width, A_NORMAL, PAIR_NUMBER(get_theme_colour(FOCUS)), NULL);
    wrefresh(cs->header);
}

static void print_all_elements(connection_screen *cs)
{
    int i = cs->base.top;

    while (cs->y < cs->base.lines && i < vector_size(cs->screen_buf)) {
        if (view == CONNECTION_PAGE)
            print_connection(cs, vector_get(cs->screen_buf, i), cs->y);
        else
            print_process(cs, vector_get(cs->screen_buf, i), cs->y);
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

static void print_header(connection_screen *cs)
{
    int y = 0;
    int x = 0;
    screen_header *p;
    unsigned int size;

    if (view == CONNECTION_PAGE) {
        p = conn_header;
        size = conn_header_size;
        mvprintat(cs->header, y, 0, get_theme_colour(HEADER_TXT), "TCP connections");
        wprintw(cs->header,  ": %d", connection_screen_get_size((screen *) cs));
        mvprintat(cs->header, ++y, 0, get_theme_colour(HEADER_TXT), "View");
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
        mvprintat(cs->header, y, 0, get_theme_colour(HEADER_TXT), "Processes");
        wprintw(cs->header,  ": %d", vector_size(cs->screen_buf));
        y += 4;
    }
    for (unsigned int i = 0; i < size; i++) {
        mvwprintw(cs->header, y, x, "%s", p[i].txt);
        x += p[i].width;
    }
    mvwchgat(cs->header, y, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
    if (cs->hpos >= 0) {
        if ((unsigned int ) cs->hpos >= size)
            cs->hpos = size - 1;
        x = 0;
        for (unsigned int i = 0; i < size; i++) {
            switch (p[i].order) {
            case HDR_INCREASING:
                mvprintat(cs->header, 4, x + p[i].width - 2, get_theme_colour(HEADER), "+");
                break;
            case HDR_DECREASING:
                mvprintat(cs->header, 4, x + p[i].width - 2, get_theme_colour(HEADER), "-");
                break;
            default:
                break;
            }
            x += p[i].width;
        }
        if (tab_active) {
            int i = 0;

            x = 0;
            while (i < cs->hpos)
                x += p[i++].width;
            mvwchgat(cs->header, 4, x, p[i].width, A_NORMAL, PAIR_NUMBER(get_theme_colour(FOCUS)), NULL);
        }
    }
    wrefresh(cs->header);
}

static void update_order(connection_screen *cs, screen_header *hdr, int size,
                         int (*cmp_elem)(const void *, const void *, void *))
{
    for (int i = 0; i < size; i++) {
        if (i != cs->hpos)
            hdr[i].order = -1;
    }
    hdr[cs->hpos].order = (hdr[cs->hpos].order + 1) % 2;
    qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
            sizeof(void *), cmp_elem, INT_TO_PTR(cs->hpos));
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
    cs->hpos = -1;
    mode = GREY_OUT_CLOSED;
    scrollok(s->win, TRUE);
    nodelay(s->win, TRUE);
    keypad(s->win, TRUE);
    update_screen_buf((screen *) cs);
    connection_data = hashmap_init(1024, hash_tcp_v4, compare_tcp_v4);
    hashmap_set_free_data(connection_data, free);
    add_subscription0(new_file_publisher, update_data);
    add_subscription0(alarm_publisher, handle_alarm);
}

void connection_screen_free(screen *s)
{
    connection_screen *cs = (connection_screen *) s;

    delwin(cs->header);
    delwin(s->win);
    vector_free(cs->screen_buf, NULL);
    hashmap_free(connection_data);
    free(cs);
}

void connection_screen_got_focus(screen *s, screen *oldscr UNUSED)
{
    if (!active) {
        s->top = 0;
        if (ctx.opt.load_file) {
            conn_header_size = ARRAY_SIZE(conn_header) - 1;
            s->num_pages = 1;
            view = CONNECTION_PAGE;
        } else {
            conn_header_size = ARRAY_SIZE(conn_header);
            s->num_pages = 2;
        }
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

void connection_screen_on_back(screen *s UNUSED)
{
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
        if (tab_active) {
            if (view == CONNECTION_PAGE)
                update_order(cs, conn_header, conn_header_size, cmp_conn);
            else
                update_order(cs, proc_header, ARRAY_SIZE(proc_header), cmp_proc);
            connection_screen_refresh(s);
        } else if (s->show_selectionbar) {
            cvs = (conversation_screen *) screen_cache_get(CONVERSATION_SCREEN);
            cvs->stream = vector_get(cs->screen_buf, s->selectionbar);
            screen_stack_move_to_top((screen *) cvs);
        }
        break;
    case 'f':
        if (view == PROCESS_PAGE)
            return;
        s->top = 0;
        mode = (mode + 1) % NUM_MODES;
        update_screen_buf(s);
        qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
                sizeof(struct tcp_connection_v4 *), cmp_conn,
                INT_TO_PTR(get_active_header_focus(conn_header, conn_header_size)));
        connection_screen_refresh(s);
        break;
    case 'p':
        if (s->num_pages == 1)
            return;
        if (view == CONNECTION_PAGE && s->show_selectionbar)
            s->show_selectionbar = false;
        view = (view + 1) % s->num_pages;
        s->top = 0;
        update_screen_buf(s);
        if (view == CONNECTION_PAGE)
            qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
                    sizeof(struct tcp_connection_v4 *), cmp_conn,
                    INT_TO_PTR(get_active_header_focus(conn_header, conn_header_size)));
        else
            qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
                    sizeof(struct process *), cmp_proc,
                    INT_TO_PTR(get_active_header_focus(proc_header, ARRAY_SIZE(proc_header))));
        connection_screen_refresh(s);
        break;
    case '\t':
        if (!tab_active) {
            tab_active = true;
            cs->hpos = -1;
        }
        handle_header_focus(s, KEY_RIGHT);
        break;
    case KEY_LEFT:
        if (tab_active)
            handle_header_focus(s, KEY_LEFT);
        break;
    case KEY_RIGHT:
        if (tab_active)
            handle_header_focus(s, KEY_RIGHT);
        break;
    case KEY_ESC:
        if (tab_active) {
            tab_active = false;
            mvwchgat(cs->header, 4, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
            wrefresh(cs->header);
            break;
        }
        FALLTHROUGH;
    default:
        s->have_selectionbar = (view == CONNECTION_PAGE);
        ungetch(c);
        screen_get_input(s);
        break;
    }
}

static unsigned int connection_screen_get_size(screen *s)
{
    return vector_size(((connection_screen *) s)->screen_buf);
}

void connection_screen_render(connection_screen *cs)
{
    touchwin(cs->header);
    touchwin(cs->base.win);
    if (ctx.capturing || vector_size(cs->screen_buf) == 0)
        update_screen_buf((screen *) cs);
    print_header(cs);
    print_all_elements(cs);
    actionbar_refresh(actionbar, (screen *) cs);
}
