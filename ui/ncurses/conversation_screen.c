#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <menu.h>
#include <sys/stat.h>
#include "layout.h"
#include "ui/print_protocol.h"
#include "error.h"
#include "jomon.h"
#include "vector.h"
#include "decoder/decoder.h"
#include "stack.h"
#include "file.h"
#include "layout.h"
#include "signal.h"
#include "dialogue.h"
#include "hexdump.h"
#include "menu.h"
#include "hashmap.h"
#include "decoder/tcp_analyzer.h"
#include "attributes.h"
#include "conversation_screen.h"
#include "main_screen_int.h"
#include "dialogue.h"
#include "process.h"
#include "actionbar.h"

#define TCP_PAGE_SIZE 1000

enum follow_tcp_mode {
    NORMAL,
    ASCII,
    RAW,
    NUM_MODES
};

struct tcp_page {
    int top;
    vector_t *buf;
};

struct tcp_page_attr {
    char *line;
    int col;
};

extern vector_t *packets;
extern main_menu *menu;
static progress_dialogue *pd = NULL;
static enum follow_tcp_mode tcp_mode = NORMAL;
static struct tcp_page tcp_page;
static bool changing_tcp_mode = false;

static void conversation_screen_init(screen *s);
static void conversation_screen_refresh(screen *s);
static void conversation_screen_get_input(screen *s);
static void conversation_screen_got_focus(screen *s, screen *oldscr);
static void conversation_screen_lost_focus(screen *s, screen *newscr);
static unsigned int conversation_screen_get_size(screen *s);
static void conversation_screen_on_back(screen *s);
static void conversation_screen_render(conversation_screen *cs);
static void print_header(conversation_screen *cs);
static void add_packet(struct tcp_connection_v4 *conn, bool new_connection);
static void change_tcp_mode(conversation_screen *cs);
static void buffer_tcppage(conversation_screen *cs, int (*buffer_fn)
                          (unsigned char *buf, int len, struct tcp_page_attr *attr, int pidx, int mx));
static int buffer_ascii(unsigned char *buf, int len, struct tcp_page_attr *attr, int pidx, int mx);
static int buffer_raw(unsigned char *buf, int len, struct tcp_page_attr *attr, int pidx, int mx);
static void print_tcppage(conversation_screen *cs);
static void handle_keyup(conversation_screen *cs, int num_lines);
static void handle_keydown(conversation_screen *cs, int num_lines);
static void scroll_page(conversation_screen *cs, int num_lines);
static void goto_home(conversation_screen *cs);
static void goto_end(conversation_screen *cs);
static void create_save_dialogue(void);
static void create_export_dialogue(void);

static screen_operations csop = {
    .screen_init = conversation_screen_init,
    .screen_free = conversation_screen_free,
    .screen_refresh = conversation_screen_refresh,
    .screen_get_input = conversation_screen_get_input,
    .screen_got_focus = conversation_screen_got_focus,
    .screen_lost_focus = conversation_screen_lost_focus,
    .screen_get_data_size = conversation_screen_get_size,
    .screen_on_back = conversation_screen_on_back
};

static void free_tcp_attr(void *arg)
{
    struct tcp_page_attr *attr = (struct tcp_page_attr *) arg;

    free(attr->line);
    free(attr);
}

static void fill_screen_buffer(conversation_screen *cs)
{
    struct packet *p;

    QUEUE_FOR_EACH(&cs->stream->packets, p, link)
        vector_push_back(cs->base.packet_ref, p);
}

conversation_screen *conversation_screen_create(void)
{
    conversation_screen *cs;

    cs = xmalloc(sizeof(conversation_screen));
    ((screen *) cs)->op = &csop;
    conversation_screen_init((screen *) cs);
    return cs;
}

void conversation_screen_init(screen *s)
{
    conversation_screen *cs = (conversation_screen *) s;

    main_screen_init(s);
    cs->stream = NULL;
    cs->base.packet_ref = NULL;
    s->show_selectionbar = true;
    memset(&tcp_page, 0, sizeof(struct tcp_page));
    tcp_page.buf = vector_init(TCP_PAGE_SIZE);
}

void conversation_screen_free(screen *s)
{
    vector_free(tcp_page.buf, free_tcp_attr);
    main_screen_free(s);
}

void conversation_screen_refresh(screen *s)
{
    conversation_screen *cs = (conversation_screen *) s;

    if (tcp_mode != NORMAL) {
        if (s->resize) {
            int my, mx;

            getmaxyx(stdscr, my, mx);
            if (my > HEADER_HEIGHT - actionbar_getmaxy(actionbar))
                wresize(s->win, my - HEADER_HEIGHT - actionbar_getmaxy(actionbar), mx);
            s->resize = false;
        }
        if (!changing_tcp_mode) {
            change_tcp_mode(cs);
        }
    } else {
        conversation_screen_render(cs);
        main_screen_refresh(s);
    }
}

void conversation_screen_got_focus(screen *s, screen *oldscr)
{
    conversation_screen *cs = (conversation_screen *) s;
    main_screen *ms = (main_screen *) cs;
    struct timespec t = {
        .tv_sec = 0,
        .tv_nsec = MS_TO_NS(100)
    };

    ms->follow_stream = true;
    tcp_analyzer_subscribe(add_packet);
    if (oldscr->fullscreen) {
        cs->base.packet_ref = vector_init(cs->stream->size);
        fill_screen_buffer(cs);
        actionbar_update(s, "F7", NULL, true);
        actionbar_update(s, "F9", NULL, true);
    }
    timer_set_callback(ms->timer, ms->timer_callback, s);
    timer_enable(ms->timer, &t);
}

void conversation_screen_lost_focus(screen *s, screen *newscr)
{
    conversation_screen *cs = (conversation_screen *) s;
    main_screen *ms = (main_screen *) cs;

    timer_disable(ms->timer);
    ms->follow_stream = false;
    tcp_analyzer_unsubscribe(add_packet);
    if (newscr->fullscreen) {
        vector_free(cs->base.packet_ref, NULL);
        s->top = 0;
        s->selectionbar = 0;
        actionbar_update(s, "F7", NULL, ctx.capturing);
        actionbar_update(s, "F9", NULL, false);
    }
}

static void conversation_screen_on_back(screen *s)
{
    ((conversation_screen *) s)->stream = NULL;
    ((main_screen *) s)->follow_stream = false;
    tcp_mode = NORMAL;
    vector_clear(tcp_page.buf, free_tcp_attr);
    tcp_page.top = 0;
}

void conversation_screen_get_input(screen *s)
{
    int c = 0;
    int my;
    conversation_screen *cs;

    cs = (conversation_screen *) s;
    if (cs->base.input_mode == INPUT_GOTO) {
        main_screen_get_input(s);
        return;
    }
    my = getmaxy(s->win);
    c = wgetch(s->win);
    switch (c) {
    case 'p':
        tcp_mode = (tcp_mode + 1) % NUM_MODES;
        change_tcp_mode(cs);
        break;
    case 'P':
        if (tcp_mode == NORMAL)
            tcp_mode = RAW;
        else
            tcp_mode = (tcp_mode - 1) % NUM_MODES;
        change_tcp_mode(cs);
        break;
    case KEY_UP:
        handle_keyup(cs, my);
        break;
    case KEY_DOWN:
        handle_keydown(cs, my);
        break;
    case KEY_LEFT:
        if (tcp_mode == NORMAL)
            main_screen_scroll_column((main_screen *) cs, -NUM_COLS_SCROLL);
        break;
    case KEY_RIGHT:
        if (tcp_mode == NORMAL)
            main_screen_scroll_column((main_screen *) cs, NUM_COLS_SCROLL);
        break;
    case KEY_ESC:
        if (((main_screen *) cs)->subwindow.win) {
            ungetch(c);
            main_screen_get_input(s);
        } else {
            conversation_screen_on_back(s);
            pop_screen();
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
    case KEY_HOME:
        if (s->show_selectionbar) {
            goto_home(cs);
        }
        break;
    case KEY_END:
        if (s->show_selectionbar) {
            goto_end(cs);
        }
        break;
    case KEY_F(5):
        if (!ctx.capturing && vector_size(cs->base.packet_ref) > 0) {
            create_save_dialogue();
        }
        break;
    case KEY_F(6):
        if (!ctx.capturing && rbtree_size(cs->base.marked) > 0)
            create_export_dialogue();
        break;
    case KEY_F(7): /* should not be enabled */
    case KEY_F(9):
    case 'e':
        break;
    default:
        /* "go to packet" should only be valid in normal mode */
        if (tcp_mode != NORMAL && c == 'g')
            break;
        ungetch(c);
        main_screen_get_input(s);
        break;
    }
}

static unsigned int conversation_screen_get_size(screen *s)
{
    return vector_size(((conversation_screen *) s)->base.packet_ref);
}

static void conversation_screen_render(conversation_screen *cs)
{
    screen *s = (screen *) cs;
    char buf[MAXLINE];
    int my = getmaxy(s->win);

    for (int i = 0; i < my && i < vector_size(cs->base.packet_ref); i++) {
        pkt2text(buf, MAXLINE, vector_get(cs->base.packet_ref, i));
        mvputsnlw(s->win, i, 0, cs->base.scrollx, buf);
    }
}

static void goto_home(conversation_screen *cs)
{
    if (tcp_mode != NORMAL) {
        tcp_page.top = 0;
        print_tcppage(cs);
    } else {
        main_screen_goto_home((main_screen*) cs);
    }
}

static void goto_end(conversation_screen *cs)
{
    int my = getmaxy(((screen *) cs)->win);

    if (tcp_mode != NORMAL) {
        if (vector_size(tcp_page.buf) > my) {
            tcp_page.top = vector_size(tcp_page.buf) - 1 - my;
            print_tcppage(cs);
        }
    } else {
        main_screen_goto_end((main_screen*) cs);
    }
}

static void handle_keyup(conversation_screen *cs, int num_lines)
{
    if (tcp_mode != NORMAL) {
        wscrl(((screen *) cs)->win, -1);
        if (tcp_page.top > 0)
            tcp_page.top--;
        print_tcppage(cs);
        wrefresh(((screen *) cs)->win);
    } else {
        main_screen_handle_keyup((main_screen*) cs, num_lines);
    }
}

static void handle_keydown(conversation_screen *cs, int num_lines)
{
    if (tcp_mode != NORMAL) {
        wscrl(((screen *) cs)->win, 1);
        tcp_page.top++;
        print_tcppage(cs);
        wrefresh(((screen *) cs)->win);
    } else {
        main_screen_handle_keydown((main_screen*) cs, num_lines);
    }
}

static void scroll_page(conversation_screen *cs, int num_lines)
{
    if (!((screen *) cs)->show_selectionbar)
        main_screen_set_interactive((main_screen *) cs, true);
    if (tcp_mode != NORMAL) {
        tcp_page.top += num_lines;
        if (tcp_page.top < 0)
            tcp_page.top = 0;
        print_tcppage(cs);
        wrefresh(((screen *) cs)->win);
    } else {
        main_screen_scroll_page((main_screen*) cs, num_lines);
    }
}

static void show_progress(int size)
{
    PROGRESS_DIALOGUE_UPDATE(pd, size);
}

static void save_handle_ok(void *file)
{
    enum file_error err;
    FILE *fp;

    if ((fp = file_open((const char *) file, "w", &err)) == NULL) {
        create_file_error_dialogue(err, create_save_dialogue);
    } else {
        char title[MAXLINE];
        conversation_screen *cs = (conversation_screen *) screen_cache_get(CONVERSATION_SCREEN);

        get_file_part(file);
        snprintf(title, MAXLINE, " Saving %s ", (char *) file);
        pd = progress_dialogue_create(title, vector_size(cs->base.packet_ref));
        push_screen((screen *) pd);
        switch (tcp_mode) {
        case NORMAL:
            file_write_pcap(ctx.handle, fp, cs->base.packet_ref, show_progress);
            break;
        case ASCII:
            file_write_ascii(fp, cs->base.packet_ref, show_progress);
            break;
        case RAW:
            file_write_raw(fp, cs->base.packet_ref, show_progress);
            break;
        default:
            break;
        }
        pop_screen();
        SCREEN_FREE((screen *) pd);
        fclose(fp);
    }
    SCREEN_FREE((screen *) save_dialogue);
    save_dialogue = NULL;
}

static void export_handle_ok(void *file)
{
    const rbtree_node_t *n;
    vector_t *tmp;
    conversation_screen *cs;

    cs = (conversation_screen *) screen_cache_get(CONVERSATION_SCREEN);
    tmp = vector_init(rbtree_size(cs->base.marked));
    RBTREE_FOREACH(cs->base.marked, n)
        vector_push_back(tmp, vector_get(cs->base.packet_ref, PTR_TO_UINT(rbtree_get_key(n)) - 1));
    main_screen_save(tmp, (const char *) file);
    vector_free(tmp, NULL);
}

static void create_save_dialogue(void)
{
    if (!save_dialogue) {
        char *info = "";

        switch (tcp_mode) {
        case NORMAL:
            info = " Save TCP stream as pcap ";
            break;
        case ASCII:
            info = " Save as ascii ";
            break;
        case RAW:
            info = " Save as raw ";
            break;
        default:
            break;
        }
        save_dialogue = file_dialogue_create(info, FS_SAVE, load_filepath, save_handle_ok,
                                             main_screen_save_handle_cancel);
        push_screen((screen *) save_dialogue);
    }
}

static void create_export_dialogue(void)
{
    if (!save_dialogue) {
        save_dialogue = file_dialogue_create(" Export marked packets as pcap ", FS_SAVE, load_filepath,
                                             export_handle_ok, main_screen_save_handle_cancel);
        push_screen((screen *) save_dialogue);
    }
}

static void change_tcp_mode(conversation_screen *cs)
{
    changing_tcp_mode = true;
    tcp_page.top = 0;
    vector_clear(tcp_page.buf, free_tcp_attr);
    switch (tcp_mode) {
    case NORMAL:
        werase(cs->base.whdr);
        werase(((screen *) cs)->win);
        main_screen_refresh((screen *) cs);
        break;
    case ASCII:
        buffer_tcppage(cs, buffer_ascii);
        print_tcppage(cs);
        break;
    case RAW:
        buffer_tcppage(cs, buffer_raw);
        print_tcppage(cs);
        break;
    default:
        break;
    }
    changing_tcp_mode = false;
}

static void buffer_tcppage(conversation_screen *cs, int (*buffer_fn)
                           (unsigned char *buf, int len, struct tcp_page_attr *attr, int pidx, int mx))
{
    int mx;
    char buf[MAXLINE];
    uint32_t cli_addr = 0;
    uint16_t cli_port = 0;
    progress_dialogue *pd;

    pd = progress_dialogue_create(" Reading packets ", vector_size(cs->base.packet_ref));
    push_screen((screen *) pd);
    mx = getmaxx(((screen *) cs)->win) - 1;
    for (int i = 0; i < vector_size(cs->base.packet_ref); i++) {
        struct packet *p = vector_get(cs->base.packet_ref, i);
        unsigned char *payload = get_adu_payload(p);
        uint16_t len;
        int n;
        int j = 0;
        int col;
        struct tcp_page_attr *attr;

        PROGRESS_DIALOGUE_UPDATE(pd, 1);
        if (i == 0) {
            cli_addr = ipv4_src(p);
            cli_port = tcp_member(p, sport);
        }
        if (cli_addr == ipv4_src(p) && cli_port == tcp_member(p, sport))
            col = get_theme_colour(SRC_TXT);
        else
            col = get_theme_colour(DST_TXT);
        buf[0] = '\0';
        len = get_adu_payload_len(p);
        if (len == 0)
            continue;
        n = snprintcat(buf, MAXLINE, "Packet %d\n", p->num);
        attr = xcalloc(1, sizeof(struct tcp_page_attr));
        attr->line = xmalloc(n + 1);
        strlcpy(attr->line, buf, n + 1);
        vector_push_back(tcp_page.buf, attr);
        n = len;
        while (n > 0) {
            int k;

            attr = xmalloc(sizeof(struct tcp_page_attr));
            k = buffer_fn(payload, n, attr, j, mx);
            attr->col = col;
            vector_push_back(tcp_page.buf, attr);
            j += k;
            n -= k;
        }
    }
    pop_screen();
    SCREEN_FREE((screen *) pd);
}

static int buffer_ascii(unsigned char *payload, int len, struct tcp_page_attr *attr, int pidx, int mx)
{
    int n;

    if (len < mx) {
        attr->line = xmalloc(len + 2);
        n = len;
    } else {
        attr->line = xmalloc(mx + 2);
        n = mx;
    }
    for (int i = 0; i < n; i++) {
        if (isprint(payload[i + pidx])) {
            attr->line[i] = payload[i + pidx];
        } else {
            attr->line[i] = '.';
        }
    }
    attr->line[n] = '\n';
    attr->line[n + 1] = '\0';
    return n;
}

static int buffer_raw(unsigned char *payload, int len, struct tcp_page_attr *attr, int pidx, int mx)
{
    int n = len;

    attr->line = xmalloc(mx + 2);
    for (int i = 0; i < len; i++) {
        if (mx - 2 * i < 0) {
            n = i;
            break;
        }
        snprintf(attr->line + 2 * i, mx - 2 * i, "%02x", payload[i + pidx]);
    }
    strcat(attr->line, "\n");
    return n;
}

static void print_tcppage(conversation_screen *cs)
{
    int my;
    struct tcp_page_attr *attr;
    int i = tcp_page.top;
    screen *s = (screen *) cs;

    scrollok(s->win, FALSE);
    print_header(cs);
    werase(s->win);
    my = getmaxy(s->win);
    while (i < my + tcp_page.top && i < vector_size(tcp_page.buf)) {
        attr = vector_get(tcp_page.buf, i);
        wattron(s->win, attr->col);
        waddstr(s->win, attr->line);
        wattroff(s->win, attr->col);
        i++;
    }
    wnoutrefresh(cs->base.whdr);
    wnoutrefresh(s->win);
    doupdate();
    scrollok(s->win, TRUE);
}

void add_packet(struct tcp_connection_v4 *conn, bool new_connection)
{
    conversation_screen *cs;

    if (new_connection)
        return;
    cs = (conversation_screen *) screen_cache_get(CONVERSATION_SCREEN);
    if (cs->stream == conn) {
        vector_push_back(cs->base.packet_ref, QUEUE_LAST(&conn->packets, struct packet, link));
        if (tcp_mode == NORMAL)
            main_screen_update((main_screen *) cs, QUEUE_LAST(&conn->packets, struct packet, link));
    }
}

void print_header(conversation_screen *cs)
{
    uint32_t cli_addr = 0;
    uint16_t cli_port = 0;
    uint32_t cli_bytes = 0;
    uint32_t srv_addr = 0;
    uint16_t srv_port = 0;
    uint32_t srv_bytes = 0;
    int cli_packets = 0;
    int srv_packets = 0;
    int txtcol = get_theme_colour(HEADER_TXT);
    char addr[INET_ADDRSTRLEN];
    char buf[64];
    int x = 0;
    screen *s = (screen *) cs;

    werase(cs->base.whdr);
    for (int i = 0; i < vector_size(cs->base.packet_ref); i++) {
        struct packet *p = vector_get(cs->base.packet_ref, i);
        uint16_t len = get_adu_payload_len(p);

        if (i == 0) {
            cli_addr = ipv4_src(p);
            cli_port = tcp_member(p, sport);
            srv_addr = ipv4_dst(p);
            srv_port = tcp_member(p, dport);
        }
        if (cli_addr == ipv4_src(p) && cli_port == tcp_member(p, sport)) {
            cli_packets++;
            cli_bytes += len;
        } else {
            srv_packets++;
            srv_bytes += len;
        }
    }
    inet_ntop(AF_INET, &cli_addr, addr, sizeof(addr));
    mvprintat(cs->base.whdr, 0, 0, txtcol, "Client address");
    if (tcp_mode == NORMAL)
        wprintw(cs->base.whdr, ": %s:%d", addr, cli_port);
    else
        printat(cs->base.whdr, get_theme_colour(SRC_TXT), ": %s:%d",
                addr, cli_port);
    mvprintat(cs->base.whdr, 0, 38, txtcol, "Packets");
    wprintw(cs->base.whdr, ": %d", cli_packets);
    mvprintat(cs->base.whdr, 0, 55, txtcol, "Bytes");
    format_bytes(cli_bytes, buf, 64);
    wprintw(cs->base.whdr, ": %s", buf);
    inet_ntop(AF_INET, &srv_addr, addr, sizeof(addr));
    mvprintat(cs->base.whdr, 1, 0, txtcol, "Server address");
    if (tcp_mode == NORMAL)
        wprintw(cs->base.whdr, ": %s:%d", addr, srv_port);
    else
        printat(cs->base.whdr, get_theme_colour(DST_TXT), ": %s:%d", addr, srv_port);
    mvprintat(cs->base.whdr, 1, 38, txtcol, "Packets");
    wprintw(cs->base.whdr, ": %d", srv_packets);
    mvprintat(cs->base.whdr, 1, 55, txtcol, "Bytes");
    format_bytes(srv_bytes, buf, 64);
    wprintw(cs->base.whdr, ": %s", buf);
    switch (tcp_mode) {
    case NORMAL:
        mvprintat(cs->base.whdr, 2, 0, txtcol, "Mode");
        wprintw(cs->base.whdr, ": Normal");
        for (unsigned int i = 0; i < s->header_size; i++) {
            mvwprintw(cs->base.whdr, 4, x, "%s", s->header[i].txt);
            x += s->header[i].width;
        }
        break;
    case ASCII:
        mvprintat(cs->base.whdr, 2, 0, txtcol, "Mode");
        wprintw(cs->base.whdr, ": Ascii");
        break;
    case RAW:
        mvprintat(cs->base.whdr, 2, 0, txtcol, "Mode");
        wprintw(cs->base.whdr, ": Raw");
        break;
    default:
        break;
    }
    mvwchgat(cs->base.whdr, HEADER_HEIGHT - 1, 0, -1, A_NORMAL,
             PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
}
