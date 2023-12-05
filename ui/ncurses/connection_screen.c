#define _GNU_SOURCE
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "connection_screen.h"
#include "help_screen.h"
#include "menu.h"
#include "decoder/tcp_analyzer.h"
#include "decoder/packet.h"
#include "decoder/packet_ip.h"
#include "jomon.h"
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
    uint64_t val;
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
static unsigned int connection_screen_get_size(screen *s);
static void connection_screen_on_back(screen *s);
static void connection_screen_render(connection_screen *cs);

static screen_operations csop = {
    .screen_init = connection_screen_init,
    .screen_free = connection_screen_free,
    .screen_refresh = connection_screen_refresh,
    .screen_get_input = connection_screen_get_input,
    .screen_got_focus = connection_screen_got_focus,
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
static enum filter_mode mode;
static hashmap_t *connection_data = NULL;

static int calculate_data(struct tcp_connection_v4 *conn, int d)
{
    uint32_t *entry;

    if ((entry = hashmap_get(connection_data, conn)) == NULL) {
        struct packet *p;

        entry = calloc(NUM_VALS, sizeof(*entry));
        entry[ADDRA] = conn->endp->src;
        entry[PORTA] = conn->endp->sport;
        entry[ADDRB] = conn->endp->dst;
        entry[PORTB] = conn->endp->dport;
        QUEUE_FOR_EACH(&conn->packets, p, link) {
            if (entry[ADDRA] == ipv4_src(p) && entry[PORTA] == tcp_member(p, sport)) {
                entry[BYTES_AB] += p->len;
                entry[PACKETS_AB]++;
            } else if (entry[ADDRB] == ipv4_src(p) &&
                       entry[PORTB] == tcp_member(p, sport)) {
                entry[BYTES_BA] += p->len;
                entry[PACKETS_BA]++;
            }
            entry[BYTES] += p->len;
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
    const node_t *n;
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
        QUEUE_FOR_EACH(&conn->packets, p, link) {
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
        return (conn_header[pos].order == HDR_INCREASING) ? c1->size - c2->size
            : c2->size - c1->size;
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
    if (s->page == CONNECTION_PAGE) {
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
        if (s->page == CONNECTION_PAGE)
            qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
                    sizeof(struct tcp_connection_v4 *), cmp_conn,
                    INT_TO_PTR(screen_get_active_header_focus(s)));
        else
            qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
                    sizeof(struct process *), cmp_proc,
                    INT_TO_PTR(screen_get_active_header_focus(s)));
        connection_screen_refresh(s);
    }
}

static void print_process(connection_screen *cs, struct process *proc, int y)
{
    char name[MAXPATH];
    int x = 0;
    const node_t *n;
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
        if (conn->endp->src == ctx.local_addr->sin_addr.s_addr) {
            entry[ADDRA].val = conn->endp->src;
            entry[PORTA].val = conn->endp->sport;
            entry[ADDRB].val = conn->endp->dst;
            entry[PORTB].val = conn->endp->dport;
        } else {
            entry[ADDRA].val = conn->endp->dst;
            entry[PORTA].val = conn->endp->dport;
            entry[ADDRB].val = conn->endp->src;
            entry[PORTB].val = conn->endp->sport;
        }
        QUEUE_FOR_EACH(&conn->packets, p, link) {
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
        QUEUE_FOR_EACH(&conn->packets, p, link) {
            if (entry[ADDRA].val == ipv4_src(p) && entry[PORTA].val == tcp_member(p, sport)) {
                entry[BYTES_AB].val += p->len;
                entry[PACKETS_AB].val++;
            } else if (entry[ADDRB].val == ipv4_src(p) &&
                       entry[PORTB].val == tcp_member(p, sport)) {
                entry[BYTES_BA].val += p->len;
                entry[PACKETS_BA].val++;
            }
            entry[BYTES].val += p->len;
        }
    }
    state = tcp_analyzer_get_connection_state(conn->state);
    strncpy(entry[STATE].buf, state, MAX_WIDTH - 1);
    entry[PACKETS].val = conn->size;
    format_bytes(entry[BYTES].val, entry[BYTES].buf, MAX_WIDTH);
    format_bytes(entry[BYTES_AB].val, entry[BYTES_AB].buf, MAX_WIDTH);
    format_bytes(entry[BYTES_BA].val, entry[BYTES_BA].buf, MAX_WIDTH);
    if (!ctx.opt.load_file)
        entry[PROCESS].str = process_get_name(conn);
    if (mode == GREY_OUT_CLOSED && (conn->state == CLOSED || conn->state == RESET))
        attrs = get_theme_colour(DISABLE);
    for (unsigned int i = 0; i < ((screen *) cs)->header_size; i++) {
        if (i % 2 == 0) {
            mvprintat(cs->base.win, y, x, attrs, "%s", entry[i].buf);
        } else {
            if (i == PROCESS) {
                if (entry[i].str) {
                    wattron(cs->base.win, attrs);
                    mvprintnlw(cs->base.win, y, x, 0, "%s", entry[i].str);
                    wattroff(cs->base.win, attrs);
                }
            } else {
                mvprintat(cs->base.win, y, x, attrs, "%lu", entry[i].val);
            }
        }
        x += conn_header[i].width;
    }
}

static void print_all_elements(connection_screen *cs)
{
    int i = cs->base.top;

    while (cs->y < cs->base.lines && i < vector_size(cs->screen_buf)) {
        if (cs->base.page == CONNECTION_PAGE)
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
    screen *s = (screen *) cs;

    if (s->page == CONNECTION_PAGE) {
        mvprintat(cs->whdr, y, 0, get_theme_colour(HEADER_TXT), "TCP connections");
        wprintw(cs->whdr,  ": %d", connection_screen_get_size((screen *) cs));
        mvprintat(cs->whdr, ++y, 0, get_theme_colour(HEADER_TXT), "View");
        switch (mode) {
        case GREY_OUT_CLOSED:
            wprintw(cs->whdr,  ": Normal");
            break;
        case REMOVE_CLOSED:
            wprintw(cs->whdr,  ": Active");
            break;
        case SHOW_ALL:
            wprintw(cs->whdr,  ": All");
            break;
        default:
            break;
        }
        y += 3;
    } else {
        mvprintat(cs->whdr, y, 0, get_theme_colour(HEADER_TXT), "Processes");
        wprintw(cs->whdr,  ": %d", vector_size(cs->screen_buf));
        y += 4;
    }
    for (unsigned int i = 0; i < s->header_size; i++) {
        mvwprintw(cs->whdr, y, x, "%s", s->header[i].txt);
        x += s->header[i].width;
    }
    screen_render_header_focus(s, cs->whdr);
    wrefresh(cs->whdr);
}

connection_screen *connection_screen_create(void)
{
    connection_screen *cs;

    cs = xmalloc(sizeof(connection_screen));
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
    s->header = conn_header;
    s->page = CONNECTION_PAGE;
    cs->whdr = newwin(CONN_HEADER, mx, 0, 0);
    cs->y = 0;
    cs->screen_buf = vector_init(512);
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

    delwin(cs->whdr);
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
            s->header_size = ARRAY_SIZE(conn_header) - 1;
            s->num_pages = 1;
            s->page = CONNECTION_PAGE;
        } else {
            s->header_size = (s->page == CONNECTION_PAGE) ? ARRAY_SIZE(conn_header) :
                ARRAY_SIZE(proc_header);
            s->num_pages = 2;
        }
        active = true;
    }
}

void connection_screen_on_back(screen *s UNUSED)
{
    active = false;
}

void connection_screen_refresh(screen *s)
{
    connection_screen *cs = (connection_screen *) s;

    werase(s->win);
    werase(cs->whdr);
    cs->y = 0;
    wbkgd(s->win, get_theme_colour(BACKGROUND));
    wbkgd(cs->whdr, get_theme_colour(BACKGROUND));
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
        if (s->tab_active) {
            if (s->page == CONNECTION_PAGE)
                screen_update_order(s, vector_data(cs->screen_buf),
                                    vector_size(cs->screen_buf), cmp_conn);
            else
                screen_update_order(s, vector_data(cs->screen_buf),
                                    vector_size(cs->screen_buf), cmp_proc);
            connection_screen_refresh(s);
        } else if (s->show_selectionbar) {
            cvs = (conversation_screen *) screen_cache_get(CONVERSATION_SCREEN);
            cvs->stream = vector_get(cs->screen_buf, s->selectionbar);
            screen_stack_move_to_top((screen *) cvs);
        }
        break;
    case 'f':
        if (s->page == PROCESS_PAGE)
            return;
        s->top = 0;
        mode = (mode + 1) % NUM_MODES;
        update_screen_buf(s);
        qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
                sizeof(struct tcp_connection_v4 *), cmp_conn,
                INT_TO_PTR(screen_get_active_header_focus(s)));
        connection_screen_refresh(s);
        break;
    case 'p':
        if (s->num_pages == 1)
            return;
        if (s->page == CONNECTION_PAGE && s->show_selectionbar)
            s->show_selectionbar = false;
        s->page = (s->page + 1) % s->num_pages;
        s->top = 0;
        update_screen_buf(s);
        if (s->page == CONNECTION_PAGE) {
            s->header = conn_header;
            s->header_size = (ctx.opt.load_file) ? ARRAY_SIZE(conn_header) - 1 :
                ARRAY_SIZE(conn_header);
            s->have_selectionbar = true;
            qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
                    sizeof(struct tcp_connection_v4 *), cmp_conn,
                    INT_TO_PTR(screen_get_active_header_focus(s)));
        } else {
            s->header = proc_header;
            s->header_size = ARRAY_SIZE(proc_header);
            s->have_selectionbar = false;
            qsort_r(vector_data(cs->screen_buf), vector_size(cs->screen_buf),
                    sizeof(struct process *), cmp_proc,
                    INT_TO_PTR(screen_get_active_header_focus(s)));
        }
        connection_screen_refresh(s);
        break;
    default:
        s->have_selectionbar = (s->page == CONNECTION_PAGE);
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
    screen *s;

    s = (screen *) cs;
    touchwin(cs->whdr);
    touchwin(cs->base.win);
    if (!s->tab_active && (ctx.capturing || vector_size(cs->screen_buf) == 0))
        update_screen_buf((screen *) cs);
    print_header(cs);
    print_all_elements(cs);
    actionbar_refresh(actionbar, (screen *) cs);
}
