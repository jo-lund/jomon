#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <menu.h>
#include <sys/stat.h>
#include "layout.h"
#include "list.h"
#include "error.h"
#include "monitor.h"
#include "vector.h"
#include "decoder/decoder.h"
#include "stack.h"
#include "file.h"
#include "signal.h"
#include "dialogue.h"
#include "main_screen.h"
#include "hexdump.h"
#include "menu.h"
#include "connection_screen.h"
#include "hashmap.h"
#include "decoder/tcp_analyzer.h"
#include "decoder/host_analyzer.h"
#include "attributes.h"
#include "main_screen_int.h"
#include "conversation_screen.h"
#include "dialogue.h"
#include "bpf/pcap_parser.h"
#include "actionbar.h"
#include "hash.h"

/* Get the y screen coordinate. The argument is the main_screen coordinate */
#define GET_SCRY(y) ((y) + HEADER_HEIGHT)

#define FILTER_IDX 8

enum input_mode {
    INPUT_NONE,
    INPUT_GOTO,
    INPUT_FILTER
};

enum key_mode {
    KEY_NORMAL,
    KEY_CTRL,
    KEY_ALT
};

extern vector_t *packets;
extern main_menu *menu;
bool selected[NUM_LAYERS];
int hexmode = HEXMODE_NORMAL;
char load_filepath[MAXPATH];
file_dialogue *load_dialogue;
file_dialogue *save_dialogue;
static enum input_mode input_mode;
static int view_mode = DECODED_VIEW;
static progress_dialogue *pd = NULL;
static bool decode_error = false;
static struct bpf_prog bpf;
static char bpf_filter[MAXLINE];
static WINDOW *status;
static enum key_mode key_mode = KEY_NORMAL;

static bool check_line(main_screen *ms);
static void print_header(main_screen *ms);
static void print_selected_packet(main_screen *ms);
static int print_lines(main_screen *ms, int from, int to, int y);
static void print_new_packets(main_screen *ms);
static void follow_tcp_stream(main_screen *ms);
static void scroll_window(main_screen *ms);
static void add_elements(main_screen *ms, struct packet *p);
static void set_filter(main_screen *ms, int c);
static void clear_filter(main_screen *ms);
static void filter_packets(main_screen *ms);
static void handle_input_mode(main_screen *ms, const char *str);
static void main_screen_save_handle_ok(void *file);
static void main_screen_export_handle_ok(void *file);

/* Handles subwindow layout */
static void create_subwindow(main_screen *ms, int num_lines, int lineno);
static void delete_subwindow(main_screen *ms, bool refresh);
static bool inside_subwindow(main_screen *ms);
static void refresh_pad(main_screen *ms, struct subwin_info *pad, int scrolly, int minx, bool update);
static bool subwindow_on_screen(main_screen *ms);

static screen_operations msop = {
    .screen_init = main_screen_init,
    .screen_free = main_screen_free,
    .screen_refresh = main_screen_refresh,
    .screen_get_input = main_screen_get_input
};

static inline void move_cursor(WINDOW *win)
{
    int y, x;

    getyx(win, y, x);
    wmove(win, y, x);
    wrefresh(win);
}

static void add_actionbar_elems(screen *s)
{
    actionbar_add(s, "F1", "Help", false);
    actionbar_add(s, "F2", "Menu", false);
    actionbar_add(s, "F3", "Start", ctx.capturing || geteuid() != 0);
    actionbar_add(s, "F4", "Stop", !ctx.capturing);
    actionbar_add(s, "F5", "Save", ctx.capturing ||
                  vector_size(((main_screen *) s)->packet_ref) == 0);
    actionbar_add(s, "F6", "Export", rbtree_size(((main_screen *) s)->marked) == 0);
    actionbar_add(s, "F7", "Load", ctx.capturing);
    actionbar_add(s, "F8", "View (dec)", false);
    actionbar_add(s, "F9", "Filter", false);
    actionbar_add(s, "F10", "Quit", false);
}

static void screen_render(main_screen *ms, int my)
{
    if (!ms->base.show_selectionbar && ctx.capturing && vector_size(ms->packet_ref) > my) {
        print_new_packets(ms);
    } else {
        if (ms->subwindow.top < 0 && abs(ms->subwindow.top) <= ms->subwindow.num_lines)
            ms->outy = print_lines(ms, ms->base.top - abs(ms->subwindow.top), ms->base.top + my, 0);
        else if (ms->subwindow.top < 0)
            ms->outy = print_lines(ms, ms->base.top - ms->subwindow.num_lines, ms->base.top + my, 0);
        else {
            ms->outy = print_lines(ms, ms->base.top, ms->base.top + my, 0);
        }
    }
}

static void set_filepath(void)
{
    int i;

    if (ctx.filename[0] != '\0') {
        i = string_find_last(ctx.filename, '/');
        if (i > 0 && i < MAXPATH) {
            strncpy(load_filepath, ctx.filename, i);
            load_filepath[i] = '\0';
            return;
        }
    }
    getcwd(load_filepath, MAXPATH);
}

main_screen *main_screen_create(void)
{
    main_screen *ms;

    ms = malloc(sizeof(main_screen));
    ms->base.op = &msop;
    main_screen_init((screen *) ms);
    return ms;
}

void main_screen_init(screen *s)
{
    main_screen *ms = (main_screen *) s;
    int my, mx;

    screen_init(s);
    getmaxyx(stdscr, my, mx);
    s->win = newwin(my - HEADER_HEIGHT - actionbar_getmaxy(actionbar), mx, HEADER_HEIGHT, 0);
    ms->outy = 0;
    ms->scrolly = 0;
    ms->scrollx = 0;
    ms->lvw = NULL;
    ms->header = newwin(HEADER_HEIGHT, mx, 0, 0);
    ms->follow_stream = false;
    ms->subwindow.top = 0;
    ms->main_line.line_number = -1;
    ms->main_line.selected = false;
    memset(&ms->subwindow, 0, sizeof(ms->subwindow));
    nodelay(s->win, TRUE); /* input functions must be non-blocking */
    keypad(s->win, TRUE);
    scrollok(s->win, TRUE);
    ms->packet_ref = packets;
    ms->marked = rbtree_init(compare_uint, NULL);
    set_filepath();
    status = newwin(1, mx, my - 1, 0);
    add_actionbar_elems(s);
}

void main_screen_free(screen *s)
{
    main_screen *ms = (main_screen *) s;

    rbtree_free(ms->marked);
    delwin(ms->subwindow.win);
    delwin(ms->header);
    delwin(ms->base.win);
    if (ms->lvw)
        free_list_view(ms->lvw);
    delwin(status);
    free(ms);
}

void main_screen_update(main_screen *ms, char *buf)
{
    int my;

    if (ms->base.focus) {
        my = getmaxy(ms->base.win);
        if (!ms->base.show_selectionbar || (ms->base.show_selectionbar && ms->outy < my)) {
            scroll_window(ms);
            mvprintnlw(ms->base.win, ms->outy, 0, ms->scrollx, buf);
            ms->outy++;
            wrefresh(ms->base.win);
            if (input_mode == INPUT_FILTER || input_mode == INPUT_GOTO)
                move_cursor(status);
        }
    }
}

void main_screen_clear(main_screen *ms)
{
    ms->base.selectionbar = 0;
    ms->base.top = 0;
    ms->outy = 0;
    main_screen_set_interactive(ms, false);
    werase(ms->header);
    werase(ms->base.win);
}

void main_screen_refresh(screen *s)
{
    int my;
    main_screen *ms;

    werase(s->win);
    ms = (main_screen *) s;
    my = getmaxy(s->win);
    wbkgd(s->win, get_theme_colour(BACKGROUND));
    wbkgd(ms->header, get_theme_colour(BACKGROUND));
    touchwin(s->win);
    if (s->resize) {
        int y, x;

        getmaxyx(stdscr, y, x);
        mvwin(status, y - 1, 0);
        my = y - HEADER_HEIGHT - actionbar_getmaxy(actionbar);
        wresize(s->win, my, x);
    }
    screen_render(ms, my);
    wnoutrefresh(s->win);
    if (ms->subwindow.win && subwindow_on_screen(ms)) {
        wbkgd(ms->subwindow.win, get_theme_colour(BACKGROUND));
        werase(ms->subwindow.win);
        if (view_mode == DECODED_VIEW)
            LV_RENDER(ms->lvw, ms->subwindow.win);
        else
            add_winhexdump(ms->subwindow.win, 0, 2, hexmode,
                           vector_get(ms->packet_ref, ms->main_line.line_number));
        if (inside_subwindow(ms))
            UPDATE_SELECTIONBAR(ms->subwindow.win, s->selectionbar - s->top -
                                ms->subwindow.top, SELECTIONBAR);
        refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, false);
    }
    if (rbtree_size(ms->marked) > 0) {
        const rbtree_node_t *n;

        RBTREE_FOREACH(ms->marked, n) {
            if (PTR_TO_UINT(rbtree_get_key(n)) - 1 >= (uint32_t) ms->base.top &&
                PTR_TO_UINT(rbtree_get_key(n)) - 1 < (uint32_t) ms->base.top + my)
                mvwchgat(ms->base.win, PTR_TO_UINT(rbtree_get_key(n)) - 1 - s->top, 0, -1, A_BOLD,
                         PAIR_NUMBER(get_theme_colour(MARK)), NULL);
        }
    }
    if (s->show_selectionbar && !inside_subwindow(ms))
        UPDATE_SELECTIONBAR(s->win, s->selectionbar - s->top, SELECTIONBAR);
    print_header(ms);
    wnoutrefresh(ms->header);
    wnoutrefresh(s->win);
    doupdate();
}

void main_screen_refresh_pad(main_screen *ms)
{
    if (ms->subwindow.win) {
        refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, true);
    }
}

void main_screen_print_packet(main_screen *ms, struct packet *p)
{
    char buf[MAXLINE];

    if (bpf.size > 0) {
        if (bpf_run_filter(bpf, p->buf, p->len) != 0) {
            vector_push_back(ms->packet_ref, p);
            write_to_buf(buf, MAXLINE, p);
            main_screen_update(ms, buf);
        }
    } else {
        write_to_buf(buf, MAXLINE, p);
        main_screen_update(ms, buf);
    }
}

static void create_load_dialogue(void)
{
    if (!load_dialogue) {
        load_dialogue = file_dialogue_create(" Load capture file ", FS_LOAD, load_filepath,
                                  main_screen_load_handle_ok, main_screen_load_handle_cancel);
        push_screen((screen *) load_dialogue);
    }
}

static void create_save_dialogue(void)
{
    if (!save_dialogue) {
        save_dialogue = file_dialogue_create(" Save displayed packets as pcap ", FS_SAVE, load_filepath,
                                             main_screen_save_handle_ok,
                                             main_screen_save_handle_cancel);
        push_screen((screen *) save_dialogue);
    }
}

static void create_export_dialogue(void)
{
    if (!save_dialogue) {
        save_dialogue = file_dialogue_create(" Export marked packets as pcap ", FS_SAVE, load_filepath,
                                             main_screen_export_handle_ok, main_screen_save_handle_cancel);
        push_screen((screen *) save_dialogue);
    }
}

static bool read_show_progress(iface_handle_t *handle, unsigned char *buffer, uint32_t n,
                               struct timeval *t)
{
    struct packet *p;
    main_screen *ms = (main_screen *) screen_cache_get(MAIN_SCREEN);

    if (!decode_packet(handle, buffer, n, &p)) {
        return false;
    }
    p->time.tv_sec = t->tv_sec;
    p->time.tv_usec = t->tv_usec;
    if (p->perr != DECODE_ERR) {
        tcp_analyzer_check_stream(p);
        host_analyzer_investigate(p);
    }
    if (bpf.size > 0)  {
        vector_push_back(packets, p);
        if (bpf_run_filter(bpf, p->buf, p->len) != 0)
            vector_push_back(ms->packet_ref, p);
    } else {
        vector_push_back(ms->packet_ref, p);
    }
    PROGRESS_DIALOGUE_UPDATE(pd, n);
    return true;
}

void main_screen_load_handle_ok(void *file)
{
    enum file_error err;
    FILE *fp;

    /* don't allow filenames containing ".." */
    if (strstr((const char *) file, "..")) {
        create_file_error_dialogue(ACCESS_ERROR, create_load_dialogue);
    } else if ((fp = file_open((const char *) file, "r", &err)) == NULL) {
        create_file_error_dialogue(err, create_load_dialogue);
    } else {
        struct stat buf[sizeof(struct stat)];
        char filename[MAXPATH + 1];
        char title[MAXLINE];
        main_screen *ms = (main_screen *) screen_cache_get(MAIN_SCREEN);
        int n;

        strcpy(filename, file);
        get_file_part(filename);
        if ((n = snprintf(title, MAXLINE, " Loading %s ", filename)) >= MAXLINE)
            string_truncate(title, MAXLINE, MAXLINE - 1);
        clear_statistics();
        vector_clear(ms->packet_ref, NULL);
        if (bpf.size > 0)
            vector_clear(packets, NULL);
        free_packets(NULL);
        lstat((const char *) file, buf);
        pd = progress_dialogue_create(title, buf->st_size);
        push_screen((screen *) pd);
        err = file_read(ctx.handle, fp, read_show_progress);
        if (err == NO_ERROR) {
            main_screen_clear(ms);
            rbtree_clear(ms->marked);
            strcpy(ctx.filename, (const char *) file);
            set_filepath();
            pop_screen();
            SCREEN_FREE((screen *) pd);
            ms->base.top = 0;
            ms->base.show_selectionbar = vector_size(ms->packet_ref) > 0;
            ctx.opt.load_file = true;
            main_screen_refresh((screen *) ms);
        } else {
            pop_screen();
            SCREEN_FREE((screen *) pd);
            memset(ctx.filename, 0, MAXPATH);
            decode_error = true;
            create_file_error_dialogue(err, create_load_dialogue);
        }
        fclose(fp);
    }
    SCREEN_FREE((screen *) load_dialogue);
    load_dialogue = NULL;
}

void main_screen_load_handle_cancel(void *d UNUSED)
{
    SCREEN_FREE((screen *) load_dialogue);
    load_dialogue = NULL;
    if (decode_error) {
        main_screen *ms;

        ms = (main_screen *) screen_cache_get(MAIN_SCREEN);
        main_screen_clear(ms);
        print_header(ms);
        wnoutrefresh(ms->header);
        wnoutrefresh(ms->base.win);
        doupdate();
        decode_error = false;
    }
}

void main_screen_save(vector_t *data, const char *file)
{
    enum file_error err;
    FILE *fp;

    if ((fp = file_open(file, "w", &err)) == NULL) {
        create_file_error_dialogue(err, create_save_dialogue);
    } else {
        char title[MAXLINE];

        get_file_part( (char *) file);
        snprintf(title, MAXLINE, " Saving %s ", (char *) file);
        pd = progress_dialogue_create(title, total_bytes);
        push_screen((screen *) pd);
        file_write_pcap(fp, data, main_screen_write_show_progress);
        pop_screen();
        SCREEN_FREE((screen *) pd);
        fclose(fp);
    }
    SCREEN_FREE((screen *) save_dialogue);
    save_dialogue = NULL;
}

void main_screen_export_handle_ok(void *file)
{
    const rbtree_node_t *n;
    vector_t *tmp;
    main_screen *ms = (main_screen *) screen_cache_get(MAIN_SCREEN);

    tmp = vector_init(rbtree_size(ms->marked));
    RBTREE_FOREACH(ms->marked, n)
        vector_push_back(tmp, vector_get(ms->packet_ref, PTR_TO_UINT(rbtree_get_key(n)) - 1));
    main_screen_save(tmp, (const char *) file);
    vector_free(tmp, NULL);
}

void main_screen_save_handle_ok(void *file)
{
    main_screen *ms = (main_screen *) screen_cache_get(MAIN_SCREEN);

    main_screen_save(ms->packet_ref, (const char *) file);
}

void main_screen_save_handle_cancel(void *d UNUSED)
{
    SCREEN_FREE((screen *) save_dialogue);
    save_dialogue = NULL;
}

void main_screen_write_show_progress(int size)
{
    PROGRESS_DIALOGUE_UPDATE(pd, size);
}

void main_screen_get_input(screen *s)
{
    int c = 0;
    int my;
    main_screen *ms;

    ms = (main_screen *) s;
    my = getmaxy(s->win);
    c = wgetch(s->win);
    switch (input_mode) {
    case INPUT_GOTO:
        main_screen_goto_line(ms, c);
        return;
    case INPUT_FILTER:
        set_filter(ms, c);
        return;
    default:
        break;
    }
    switch (c) {
    case 'f':
        if (s->show_selectionbar && !inside_subwindow(ms))
            follow_tcp_stream(ms);
        break;
    case 'g':
        if (!s->show_selectionbar)
            return;
        input_mode = (input_mode == INPUT_GOTO) ? INPUT_NONE : INPUT_GOTO;
        handle_input_mode(ms, "Go to line: ");
        break;
    case 'i':
        main_screen_set_interactive(ms, !s->show_selectionbar);
        break;
    case 'm':
        hexmode = (hexmode + 1) % HEXMODES;
        if (ms->subwindow.win) {
            struct packet *p;

            p = vector_get(ms->packet_ref, ms->main_line.line_number);
            if (view_mode == HEXDUMP_VIEW) {
                delete_subwindow(ms, true);
                create_subwindow(ms, (hexmode == HEXMODE_NORMAL) ? p->len / 16 + 3 :
                                 p->len / 64 + 3, ms->main_line.line_number);
            } else {
                delete_subwindow(ms, true);
                add_elements(ms, p);
                create_subwindow(ms, ms->lvw->size + 1, ms->main_line.line_number);
            }
            main_screen_refresh((screen *) ms);
        }
        break;
    case KEY_CTRL_UP:
        key_mode = KEY_CTRL;
        FALLTHROUGH;
    case KEY_UP:
        main_screen_handle_keyup(ms, my);
        break;
    case KEY_CTRL_DOWN:
        key_mode = KEY_CTRL;
        FALLTHROUGH;
    case KEY_DOWN:
        main_screen_handle_keydown(ms, my);
        break;
    case KEY_LEFT:
        main_screen_scroll_column(ms, -NUM_COLS_SCROLL);
        break;
    case KEY_RIGHT:
        main_screen_scroll_column(ms, NUM_COLS_SCROLL);
        break;
    case KEY_ENTER:
    case '\n':
        if (s->show_selectionbar)
            print_selected_packet(ms);
        break;
    case KEY_ESC:
            if (ms->subwindow.win) {
                delete_subwindow(ms, true);
                ms->main_line.selected = false;
            } else if (s->show_selectionbar) {
                main_screen_set_interactive(ms, false);
            }
        break;
    case ' ':
    case KEY_NPAGE:
        main_screen_scroll_page(ms, my);
        break;
    case 'b':
    case KEY_PPAGE:
        main_screen_scroll_page(ms, -my);
        break;
    case KEY_HOME:
        if (s->show_selectionbar) {
            main_screen_goto_home(ms);
        }
        break;
    case KEY_END:
        if (s->show_selectionbar) {
            main_screen_goto_end(ms);
        }
        break;
    case KEY_F(3):
    {
        uid_t euid = geteuid();

        if (!ctx.capturing && euid == 0) {
            main_screen_clear(ms);
            start_scan();
            print_header(ms);
            wnoutrefresh(s->win);
            wnoutrefresh(ms->header);
            actionbar_update(s, "F3", NULL, true);
            actionbar_update(s, "F4", NULL, false);
            actionbar_update(s, "F5", NULL, true);
            actionbar_update(s, "F6", NULL, true);
            actionbar_update(s, "F7", NULL, true);
            doupdate();
        }
        break;
    }
    case KEY_F(4):
        if (ctx.capturing) {
            if (!s->show_selectionbar)
                main_screen_set_interactive(ms, true);
            stop_scan();
            actionbar_update(s, "F3", NULL, false);
            actionbar_update(s, "F4", NULL, true);
            actionbar_update(s, "F5", NULL, !vector_size(ms->packet_ref));
            actionbar_update(s, "F6", NULL, !rbtree_size(ms->marked));
            actionbar_update(s, "F7", NULL, false);
        }
        break;
    case KEY_F(5):
        if (!ctx.capturing && vector_size(ms->packet_ref) > 0) {
            create_save_dialogue();
        }
        break;
    case KEY_F(6):
        if (!ctx.capturing && rbtree_size(ms->marked) > 0)
            create_export_dialogue();
        break;
    case KEY_F(7):
        if (!ctx.capturing) {
            create_load_dialogue();
        }
        break;
    case KEY_F(8):
        view_mode = (view_mode + 1) % NUM_VIEWS;
        if (ms->subwindow.win) {
            struct packet *p;

            delete_subwindow(ms, true);
            p = vector_get(ms->packet_ref, ms->main_line.line_number);
            if (view_mode == DECODED_VIEW) {
                add_elements(ms, p);
                create_subwindow(ms, ms->lvw->size + 1, ms->main_line.line_number);
            } else {
                create_subwindow(ms, (hexmode == HEXMODE_NORMAL) ? p->len / 16 + 3 :
                                 p->len / 64 + 3, ms->main_line.line_number);
            }
            main_screen_refresh((screen *) ms);
        }
        actionbar_update(s, "F8", (view_mode == DECODED_VIEW) ? "View (dec)" :
                         "View (hex)", false);
        break;
    case 'e':
    case KEY_F(9):
        input_mode = (input_mode == INPUT_FILTER) ? INPUT_NONE : INPUT_FILTER;
        handle_input_mode(ms, "Filter: ");
        break;
    case 'M':
        if (!ctx.capturing && !inside_subwindow(ms)) {
            if (rbtree_contains(ms->marked, UINT_TO_PTR(s->selectionbar + 1)))
                rbtree_remove(ms->marked, UINT_TO_PTR(s->selectionbar + 1));
            else
                rbtree_insert(ms->marked, UINT_TO_PTR(s->selectionbar + 1), NULL);
            actionbar_update(s, "F6", NULL, rbtree_size(ms->marked) == 0);
            main_screen_handle_keydown(ms, my);
        }
        break;
    default:
        ungetch(c);
        screen_get_input(s);
        break;
    }
    key_mode = KEY_NORMAL;
}

/* scroll the window if necessary */
void scroll_window(main_screen *ms)
{
    int my;

    my = getmaxy(ms->base.win);
    if (ms->outy >= my) {
        ms->outy = my - 1;
        scroll(ms->base.win);
        ms->base.top++;
    }
}

void print_header(main_screen *ms)
{
    int y = 0;
    int x = 0;
    char addr[INET_ADDRSTRLEN];
    int txtcol = get_theme_colour(HEADER_TXT);
    char mac[HW_ADDRSTRLEN];
    int maxx = getmaxx(stdscr);
    char file[MAXPATH];

    werase(ms->header);

    if (ctx.filename[0] && ctx.opt.load_file) {
        strncpy(file, ctx.filename, MAXPATH);
        mvprintat(ms->header, y, 0, txtcol, "Filename");
        wprintw(ms->header, ": %s", get_file_part(file));
    } else {
        mvprintat(ms->header, y, 0, txtcol, "Device");
        wprintw(ms->header, ": %s", ctx.device);
    }
    mvprintat(ms->header, y, maxx / 2, txtcol, "Display filter");
    if (bpf.size != 0)
        wprintw(ms->header, ": %s", bpf_filter);
    else
        wprintw(ms->header, ": None");
    inet_ntop(AF_INET, &ctx.local_addr->sin_addr, addr, sizeof(addr));
    mvprintat(ms->header, ++y, 0, txtcol, "IPv4 address");
    wprintw(ms->header, ": %s", addr);
    mvprintat(ms->header, y, maxx / 2, txtcol, "Follow stream");
    if (ms->follow_stream)
        wprintw(ms->header, ": %u", ((conversation_screen *) ms)->stream->num);
    else
        wprintw(ms->header, ": None");
    HW_ADDR_NTOP(mac, ctx.mac);
    mvprintat(ms->header, ++y, 0, txtcol, "MAC");
    wprintw(ms->header, ": %s", mac);
    y += 2;
    for (unsigned int i = 0; i < ARRAY_SIZE(main_header); i++) {
        mvwprintw(ms->header, y, x, "%s", main_header[i].txt);
        x += main_header[i].width;
    }
    mvwchgat(ms->header, HEADER_HEIGHT - 1, 0, -1, A_NORMAL,
             PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
}

void handle_input_mode(main_screen *ms, const char *str)
{
    switch (input_mode) {
    case INPUT_FILTER:
    case INPUT_GOTO:
        werase(status);
        mvwprintw(status, 0, 0, "%s", str);
        curs_set(1);
        wrefresh(status);
        break;
    case INPUT_NONE:
        curs_set(0);
        werase(status);
        actionbar_refresh(actionbar, (screen *) ms);
        break;
    default:
        break;
    }
}

void main_screen_goto_line(main_screen *ms, int c)
{
    static int num = 0;

    if (isdigit(c) && num < INT_MAX / 10) {
        waddch(status, c);
        num = num * 10 + c - '0';
        wrefresh(status);
    } else if (c == KEY_BACKSPACE || c == 127 || c == '\b') {
        int x, y;

        getyx(status, y, x);
        if (x >= 13) {
            mvwdelch(status, y, x - 1);
            num /= 10;
        }
        wrefresh(status);
    } else if (num && (c == '\n' || c == KEY_ENTER)) {
        if (num > ms->subwindow.num_lines + vector_size(ms->packet_ref))
            return;

        int my;

        my = getmaxy(ms->base.win);
        if (num >= ms->base.top && num < ms->base.top + my - ms->subwindow.num_lines) {
            if (ms->subwindow.win && num > ms->base.top + ms->subwindow.top) {
                ms->base.selectionbar = num - 1 + ms->subwindow.num_lines;
            } else {
                ms->base.selectionbar = num - 1;
            }
        } else {
            if (ms->subwindow.win)
                delete_subwindow(ms, false);
            if (num + my - 1 > vector_size(ms->packet_ref)) {
                ms->base.top = vector_size(ms->packet_ref) - my;
                ms->base.selectionbar = num - 1;
            } else {
                ms->base.selectionbar = ms->base.top = num - 1;
            }
        }
        curs_set(0);
        werase(status);
        input_mode = INPUT_NONE;
        num = 0;
        actionbar_refresh(actionbar, (screen *) ms);
        main_screen_refresh((screen *) ms);
    } else if (c == KEY_ESC) {
        curs_set(0);
        werase(status);
        num = 0;
        input_mode = INPUT_NONE;
        actionbar_refresh(actionbar, (screen *) ms);
    }
}

void main_screen_goto_home(main_screen *ms)
{
    if (ms->subwindow.win)
        ms->subwindow.top += ms->base.top;
    ms->base.selectionbar = 0;
    ms->base.top = 0;
    main_screen_refresh((screen *) ms);
}

void main_screen_goto_end(main_screen *ms)
{
    int my = getmaxy(ms->base.win);

    if (vector_size(ms->packet_ref) >= my) {
        if (ms->subwindow.win) {
            int scroll;

            scroll = vector_size(ms->packet_ref) - my - ms->base.top + ms->subwindow.num_lines;
            ms->base.top = vector_size(ms->packet_ref) - my + ms->subwindow.num_lines;
            ms->base.selectionbar = vector_size(ms->packet_ref) - 1 + ms->subwindow.num_lines;
            ms->subwindow.top -= scroll;
        } else {
            ms->base.top = vector_size(ms->packet_ref) - my;
            ms->base.selectionbar = vector_size(ms->packet_ref) - 1;
        }
    }
    main_screen_refresh((screen *) ms);
}

void set_filter(main_screen *ms, int c)
{
    static int numc = 0;
    struct bpf_prog prog;
    char filter[MAXLINE];
    int x, y;

    switch (c) {
    case '\n':
    case KEY_ENTER:
        getyx(status, y, x);
        curs_set(0);
        mvwinnstr(status, 0, 8, filter, MAXLINE);
        filter[numc] = '\0';
        if (ms->subwindow.win) {
            delete_subwindow(ms, false);
            ms->main_line.selected = false;
        }
        if (numc == 0) {
            clear_filter(ms);
        } else {
            prog = pcap_compile(filter);
            if (prog.size == 0) {
                wbkgd(status, get_theme_colour(ERR_BKGD));
                wmove(status, y, x);
                curs_set(1);
                wrefresh(status);
                return;
            }
            if (bpf.size > 0) {
                free(bpf.bytecode);
                vector_free(ms->packet_ref, NULL);
            }
            bpf = prog;
            strncpy(bpf_filter, filter, MAXLINE);
            filter_packets(ms);
            if (vector_size(ms->packet_ref) == 0)
                ms->base.show_selectionbar = false;
        }
        input_mode = INPUT_NONE;
        werase(status);
        actionbar_refresh(actionbar, (screen *) ms);
        ms->base.top = 0;
        ms->base.selectionbar = 0;
        wbkgd(status, get_theme_colour(BACKGROUND));
        numc = 0;
        main_screen_refresh((screen *) ms);
        break;
    case KEY_ESC:
        curs_set(0);
        numc = 0;
        input_mode = INPUT_NONE;
        werase(status);
        wbkgd(status, get_theme_colour(BACKGROUND));
        actionbar_refresh(actionbar, (screen *) ms);
        break;
    case KEY_BACKSPACE:
    case 127:
    case '\b':
        getyx(status, y, x);
        if (x > FILTER_IDX) {
            mvwdelch(status, y, x - 1);
            numc--;
            wrefresh(status);
        }
        break;
    case KEY_LEFT:
        getyx(status, y, x);
        if (x > FILTER_IDX) {
            wmove(status, 0, x - 1);
            wrefresh(status);
        }
        break;
    case KEY_RIGHT:
        getyx(status, y, x);
        if (x - FILTER_IDX < numc) {
            wmove(status, 0, x + 1);
            wrefresh(status);
        }
        break;
    case KEY_DC:
        getyx(status, y, x);
        if (x - FILTER_IDX < numc) {
            mvwdelch(status, 0, x);
            numc--;
            wrefresh(status);
        }
        break;
    default:
        if (c >= 0x20 && c < 0x7f) {
            waddch(status, c);
            numc++;
            wrefresh(status);
        }
        break;
    }
}

void clear_filter(main_screen *ms)
{
    if (bpf.size > 0) {
        free(bpf.bytecode);
        bpf.size = 0;
        vector_free(ms->packet_ref, NULL);
        ms->packet_ref = packets;
    }
    memset(bpf_filter, 0, sizeof(bpf_filter));
}

void filter_packets(main_screen *ms)
{
    ms->packet_ref = vector_init(PACKET_TABLE_SIZE);
    for (int i = 0; i < vector_size(packets); i++) {
        struct packet *p = vector_get(packets, i);

        if (bpf_run_filter(bpf, p->buf, p->len) != 0)
            vector_push_back(ms->packet_ref, p);
    }
}

void print_new_packets(main_screen *ms)
{
    int c = vector_size(ms->packet_ref) - 1;
    int my = getmaxy(ms->base.win);

    werase(ms->base.win);

    /* print the new packets stored in vector from bottom to top of screen */
    for (int i = my - 1; i >= 0; i--, c--) {
        struct packet *p;
        char buffer[MAXLINE];

        p = vector_get(ms->packet_ref, c);
        write_to_buf(buffer, MAXLINE, p);
        mvprintnlw(ms->base.win, i, 0, ms->scrollx, buffer);
    }
    ms->base.top = c + 1;
    ms->outy = my;
}

/*
 * Checks if there still are lines to highlight when moving the selection bar
 * down. Returns true if that's the case.
 */
static inline bool check_line(main_screen *ms)
{
    return ms->base.selectionbar < vector_size(ms->packet_ref) +
        ms->subwindow.num_lines - 1;
}

static void goto_selectable(main_screen *ms, int num_lines, int c)
{
    int subline;
    int scroll;

    if (!ms->subwindow.win || !inside_subwindow(ms))
        return;
    subline = ms->base.selectionbar - ms->base.top - ms->subwindow.top;
    if (c == KEY_DOWN) {
        if (view_mode == HEXDUMP_VIEW && inside_subwindow(ms)) {
            ms->base.selectionbar += (ms->subwindow.num_lines - subline);
        } else {
            while (inside_subwindow(ms) && LV_GET_DATA(ms->lvw, subline) == -1 &&
               ms->base.selectionbar < vector_size(ms->packet_ref) +
                   ms->subwindow.num_lines - 1) {
                ms->base.selectionbar++;
                subline++;
            }
        }
        if (ms->base.selectionbar - ms->base.top >= num_lines - 1) {
            scroll = ms->base.selectionbar - (ms->base.top + num_lines - 1);
            ms->base.top += scroll;
            refresh_pad(ms, &ms->subwindow, -scroll, ms->scrollx, false);
        }
    } else {
        if (view_mode == HEXDUMP_VIEW && inside_subwindow(ms)) {
            ms->base.selectionbar -= (subline + 1);
        } else {
            while (inside_subwindow(ms) && LV_GET_DATA(ms->lvw, subline) == -1 &&
                   ms->base.selectionbar > 0) {
                ms->base.selectionbar--;
                subline--;
            }
        }
        if (ms->base.selectionbar <= ms->base.top) {
            scroll = ms->base.top - ms->base.selectionbar;
            if (ms->base.top - scroll < 0)
                scroll = ms->base.top;
            ms->base.top -= scroll;
            refresh_pad(ms, &ms->subwindow, scroll, ms->scrollx, false);
        }
    }
}

void main_screen_scroll_column(main_screen *ms, int scrollx)
{
    if ((scrollx < 0 && ms->scrollx) || scrollx > 0) {
        ms->scrollx += scrollx;
        main_screen_refresh((screen *) ms);
    }
}

void main_screen_handle_keyup(main_screen *ms, int num_lines UNUSED)
{
    if (!ms->base.show_selectionbar)
        main_screen_set_interactive(ms, true);

    /* scroll screen if the selection bar is at the top */
    if (ms->base.top > 0 && ms->base.selectionbar == ms->base.top) {
        ms->base.selectionbar--;
        ms->base.top--;
        if (ms->subwindow.win) {
            refresh_pad(ms, &ms->subwindow, 1, ms->scrollx, false);
            if (key_mode == KEY_CTRL)
                goto_selectable(ms, num_lines, KEY_UP);
        }
    } else if (ms->base.selectionbar > 0) {
        ms->base.selectionbar--;
        if (key_mode == KEY_CTRL)
            goto_selectable(ms, num_lines, KEY_UP);
    }
    main_screen_refresh((screen *) ms);
}

void main_screen_handle_keydown(main_screen *ms, int num_lines)
{
    if (!check_line(ms))
        return;
    if (!ms->base.show_selectionbar)
        main_screen_set_interactive(ms, true);

    /* scroll screen if the selection bar is at the bottom */
    if (ms->base.selectionbar - ms->base.top == num_lines - 1) {
        ms->base.top++;
        ms->base.selectionbar++;
        if (ms->subwindow.win) {
            refresh_pad(ms, &ms->subwindow, -1, ms->scrollx, false);
            if (key_mode == KEY_CTRL)
                goto_selectable(ms, num_lines, KEY_DOWN);
        }
    } else {
        ms->base.selectionbar++;
        if (key_mode == KEY_CTRL)
            goto_selectable(ms, num_lines, KEY_DOWN);
    }
    main_screen_refresh((screen *) ms);
}

void main_screen_scroll_page(main_screen *ms, int num_lines)
{
    if (!ms->base.show_selectionbar) {
        main_screen_set_interactive(ms, true);
    }
    if (num_lines > 0) { /* scroll page down */
        if (vector_size(ms->packet_ref) + ms->subwindow.num_lines <= num_lines) {
            if (ms->subwindow.win) {
                ms->base.selectionbar = ms->subwindow.num_lines + vector_size(ms->packet_ref) - 1;
            } else {
                ms->base.selectionbar = vector_size(ms->packet_ref) - 1;
            }
            main_screen_refresh((screen *) ms);
        } else {
            int bottom = ms->base.top + num_lines - 1;

            if (bottom + num_lines > vector_size(ms->packet_ref) - 1 + ms->subwindow.num_lines) {
                int scroll = vector_size(ms->packet_ref) - bottom - 1 + ms->subwindow.num_lines;

                ms->base.top += scroll;
                ms->base.selectionbar += num_lines;
                if (ms->base.selectionbar >= vector_size(ms->packet_ref) + ms->subwindow.num_lines) {
                    ms->base.selectionbar = vector_size(ms->packet_ref) - 1 + ms->subwindow.num_lines;
                }
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, -scroll, ms->scrollx, false);
                }
                main_screen_refresh((screen *) ms);
            } else {
                ms->base.selectionbar += num_lines;
                ms->base.top += num_lines;
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, -num_lines, ms->scrollx, false);
                }
                main_screen_refresh((screen *) ms);
            }
        }
    } else { /* scroll page up */
        if (vector_size(ms->packet_ref) + ms->subwindow.num_lines <= abs(num_lines) || ms->base.top == 0) {
            ms->base.selectionbar = 0;
            main_screen_refresh((screen *) ms);
        } else {
            ms->base.selectionbar += num_lines;
            if (ms->base.top + num_lines < 0) {
                if (ms->base.selectionbar < 0) {
                    ms->base.selectionbar = 0;
                }
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, ms->base.top, ms->scrollx, false);
                }
                ms->base.top = 0;
                main_screen_refresh((screen *) ms);
            } else {
                ms->base.top -= abs(num_lines);
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, abs(num_lines), ms->scrollx, false);
                }
                main_screen_refresh((screen *) ms);
            }
        }
    }
}

void main_screen_set_interactive(main_screen *ms, bool interactive_mode)
{
    if (!vector_size(ms->packet_ref)) {
        ms->base.show_selectionbar = false;
        return;
    }
    if (interactive_mode) {
        ms->base.show_selectionbar = true;
        ms->base.selectionbar = ms->base.top;
    } else {
        if (ms->subwindow.win) {
            delete_subwindow(ms, true);
            ms->main_line.selected = false;
        }
        ms->base.show_selectionbar = false;
    }
    main_screen_refresh((screen *) ms);
}

/*
 * Prints lines in the interval [from, to). 'y' specifies where on the screen it
 * will start to print. Returns how many lines are actually printed.
 */
int print_lines(main_screen *ms, int from, int to, int y)
{
    int c = 0;
    int line = from;

    while (line < to) {
        struct packet *p;
        char buffer[MAXLINE];

        if (ms->subwindow.win && y >= ms->subwindow.top && ms->subwindow.top < to - ms->base.top &&
            y < ms->subwindow.top + ms->subwindow.num_lines) {
            y++;
        } else {
            p = vector_get(ms->packet_ref, from);
            if (!p) break;
            write_to_buf(buffer, MAXLINE, p);
            if (ms->scrollx) {
                int n = strlen(buffer);

                if (ms->scrollx < n) {
                    mvprintnlw(ms->base.win, y++, 0, ms->scrollx, buffer);
                } else {
                    y++;
                }
            } else {
                mvprintnlw(ms->base.win, y++, 0, ms->scrollx, buffer);
            }
            from++;
        }
        line++;
        c++;
    }
    return c;
}

/*
 * Print more information about a packet when selected. This will print more
 * details about the specific protocol headers and payload.
 */
void print_selected_packet(main_screen *ms)
{
    int screen_line;
    struct packet *p;
    static int prev_selection = -1;

    if (prev_selection >= 0 && ms->subwindow.win) {
        if (inside_subwindow(ms)) {
            int subline;
            int32_t data;

            /* the window contains no selectable elements */
            if (view_mode == HEXDUMP_VIEW)
                return;

            /* update the selection status of the selectable subwindow line */
            screen_line = ms->base.selectionbar - ms->base.top;
            subline = screen_line - ms->subwindow.top;
            if ((data = LV_GET_DATA(ms->lvw, subline)) == -1)
                return;
            LV_SET_EXPANDED(ms->lvw, subline, !LV_GET_EXPANDED(ms->lvw, subline));
            if (data >= 0 && data < NUM_LAYERS)
                selected[data] = LV_GET_EXPANDED(ms->lvw, subline);
            if (ms->subwindow.win)
                delete_subwindow(ms, false);
            create_subwindow(ms, ms->lvw->size + 1, prev_selection);
            main_screen_refresh((screen *) ms);
            return;
        }
    }
    screen_line = ms->base.selectionbar - ms->base.top;
    if (ms->base.selectionbar == ms->main_line.line_number) {
        ms->main_line.selected = !ms->main_line.selected;
    } else {
        ms->main_line.selected = true;

        /* the index to the selected line needs to be adjusted in case of an
           open subwindow */
        if (ms->subwindow.win) {
            if (subwindow_on_screen(ms) && screen_line > ms->subwindow.top) {
                if (ms->subwindow.top < 0)
                    ms->base.top = MAX(ms->base.top - ms->subwindow.num_lines, 0);
                ms->base.selectionbar -= ms->subwindow.num_lines;
            } else if (ms->subwindow.top < 0) {
                ms->base.top -= ms->subwindow.num_lines;
                ms->base.selectionbar -= ms->subwindow.num_lines;
            }
        }
        ms->main_line.line_number = ms->base.selectionbar;
    }
    if (ms->main_line.selected) {
        p = vector_get(ms->packet_ref, ms->base.selectionbar);
        if (view_mode == DECODED_VIEW) {
            add_elements(ms, p);
            if (ms->subwindow.win)
                delete_subwindow(ms, false);
            create_subwindow(ms, ms->lvw->size + 1, ms->base.selectionbar);
        } else {
            if (ms->subwindow.win)
                delete_subwindow(ms, false);
            create_subwindow(ms, (hexmode == HEXMODE_NORMAL) ? p->len / 16 + 3 :
                             p->len / 64 + 3, ms->base.selectionbar);
        }
        main_screen_refresh((screen *) ms);
    } else {
        delete_subwindow(ms, true);
    }
    prev_selection = ms->base.selectionbar;
}

void add_elements(main_screen *ms, struct packet *p)
{
    list_view_header *header;
    struct protocol_info *pinfo;
    struct packet_data *pdata;
    int i = 0;
    int idx = 0;

    if (ms->lvw) {
        free_list_view(ms->lvw);
    }
    ms->lvw = create_list_view();
    pdata = p->root;

    /* add packet headers as elements to the list view */
    while (pdata) {
        pinfo = get_protocol(pdata->id);
        idx += pdata->len;
        if (pinfo && i < NUM_LAYERS) {
            if (pdata && pdata->data) {
                header = LV_ADD_HEADER(ms->lvw, pinfo->long_name, selected[i], i);
                pinfo->add_pdu(ms->lvw, header, pdata);
            }
        }
        i++;
        pdata = pdata->next;
    }
    if (p->perr != NO_ERR && (int) p->len - idx > 0) {
        header = LV_ADD_HEADER(ms->lvw, "Data", selected[i], i);
        add_hexdump(ms->lvw, header, hexmode, p->buf + idx, p->len - idx);
    }
}

void create_subwindow(main_screen *ms, int num_lines, int lineno)
{
    int mx, my;
    int start_line;
    int c;

    getmaxyx(ms->base.win, my, mx);
    start_line = lineno - ms->base.top;
    c = lineno + 1;

    /* if there is not enough space for the information to be printed, the
       screen needs to be scrolled to make room for all the lines */
    if (my - (start_line + 1) < num_lines) {
        ms->scrolly = (num_lines >= my) ? start_line : num_lines - (my - (start_line + 1));
        start_line -= ms->scrolly;
        ms->base.top += ms->scrolly;
        if (ms->base.selectionbar < ms->base.top)
            ms->base.selectionbar = ms->base.top;
    }
    ms->subwindow.win = newpad(num_lines, mx);
    wbkgd(ms->subwindow.win, get_theme_colour(BACKGROUND));
    scrollok(ms->subwindow.win, TRUE);
    ms->subwindow.top = start_line + 1;
    ms->subwindow.num_lines = num_lines;
    wmove(ms->base.win, start_line + 1, 0);
    wclrtobot(ms->base.win); /* clear everything below selection bar */
    ms->outy = start_line + 1;
    if (!ms->scrolly) {
        ms->outy += print_lines(ms, c, ms->base.top + my, ms->outy);
    } else {
        ms->outy += num_lines;
    }
}

void delete_subwindow(main_screen *ms, bool refresh)
{
    if (ms->scrolly) {
        if (ms->subwindow.top > 0 && subwindow_on_screen(ms))
            ms->base.top = MAX(ms->base.top - ms->scrolly, 0);
        ms->scrolly = 0;
    }
    delwin(ms->subwindow.win);
    ms->subwindow.win = NULL;
    if (refresh) {
        int my = getmaxy(ms->base.win);

        if (ms->base.selectionbar >= vector_size(ms->packet_ref))
            ms->base.selectionbar = vector_size(ms->packet_ref) - 1;
        if (ms->base.top >= vector_size(ms->packet_ref) ||
            (subwindow_on_screen(ms) && ms->subwindow.top < 0)) {
            if (vector_size(ms->packet_ref) < my)
                ms->base.top = 0;
            else
                ms->base.top = ms->main_line.line_number;
            ms->base.selectionbar = ms->main_line.line_number;
        } else if (ms->base.selectionbar >= ms->base.top + getmaxy(ms->base.win)) {
            ms->base.selectionbar = ms->base.top + getmaxy(ms->base.win) - 1;
        }
        ms->subwindow.num_lines = 0;
        ms->subwindow.top = 0;
        main_screen_refresh((screen *) ms);
    } else {
        ms->subwindow.num_lines = 0;
        ms->subwindow.top = 0;
    }
}

/* Returns whether the selection line is inside the subwindow */
static inline bool inside_subwindow(main_screen *ms)
{
    int subline = ms->base.selectionbar - ms->base.top - ms->subwindow.top;

    return ms->subwindow.win && subline >= 0 && subline < ms->subwindow.num_lines;
}

/* Returns whether the subwindow is shown on screen */
static inline bool subwindow_on_screen(main_screen *ms)
{
    return ((ms->subwindow.top <= 0 && abs(ms->subwindow.top) < ms->subwindow.num_lines) ||
            (ms->subwindow.top > 0 && ms->subwindow.top < getmaxy(ms->base.win)));
}

/*
 * Refresh the pad.
 *
 * 'scrolly' is the amount to scroll the pad vertically inside the main window.
 * 'minx' is the x-coordinate that decides where to start showing information within
 * the pad.
 */
void refresh_pad(main_screen *ms, struct subwin_info *pad, int scrolly, int minx, bool update)
{
    int my, mx;

    getmaxyx(ms->base.win, my, mx);
    pad->top += scrolly;
    if (pad->top <= 0) {
        if (update) {
            prefresh(pad->win, abs(pad->top), minx, GET_SCRY(0), 0, GET_SCRY(my) - 1, mx);
        } else {
            pnoutrefresh(pad->win, abs(pad->top), minx, GET_SCRY(0), 0, GET_SCRY(my) - 1, mx);
        }
    } else {
        if (update) {
            prefresh(pad->win, 0, minx, GET_SCRY(pad->top), 0, GET_SCRY(my) - 1, mx);
        } else {
            pnoutrefresh(pad->win, 0, minx, GET_SCRY(pad->top), 0, GET_SCRY(my) - 1, mx);
        }
    }
}

static void follow_tcp_stream(main_screen *ms)
{
    hashmap_t *connections = tcp_analyzer_get_sessions();
    struct packet *p = vector_get(ms->packet_ref, ms->base.selectionbar);
    struct tcp_connection_v4 *stream;
    struct tcp_endpoint_v4 endp;
    conversation_screen *cs = (conversation_screen *) screen_cache_get(CONVERSATION_SCREEN);

    if (!is_tcp(p) || ethertype(p) != ETHERTYPE_IP)
        return;
    endp.src = ipv4_src(p);
    endp.dst = ipv4_dst(p);
    endp.sport = tcp_member(p, sport);
    endp.dport = tcp_member(p, dport);
    if (!(stream = hashmap_get(connections, &endp))) {
        endp.src = ipv4_dst(p);
        endp.dst = ipv4_src(p);
        endp.sport = tcp_member(p, dport);
        endp.dport = tcp_member(p, sport);
        stream = hashmap_get(connections, &endp);
    }
    cs->stream = stream;
    screen_stack_move_to_top((screen *) cs);
}
