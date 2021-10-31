#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <menu.h>
#include <sys/stat.h>
#include "layout.h"
#include "protocols.h"
#include "../list.h"
#include "../error.h"
#include "../monitor.h"
#include "../vector.h"
#include "../decoder/decoder.h"
#include "../stack.h"
#include "../file.h"
#include "layout_int.h"
#include "../signal.h"
#include "dialogue.h"
#include "main_screen.h"
#include "hexdump.h"
#include "menu.h"
#include "connection_screen.h"
#include "../hashmap.h"
#include "../decoder/tcp_analyzer.h"
#include "../decoder/host_analyzer.h"
#include "../attributes.h"
#include "main_screen_int.h"
#include "conversation_screen.h"
#include "dialogue.h"
#include "../bpf/pcap_parser.h"
#include "actionbar.h"

/* Get the y screen coordinate. The argument is the main_screen coordinate */
#define GET_SCRY(y) ((y) + HEADER_HEIGHT)

#define FILTER_IDX 8

enum input_mode {
    INPUT_NONE,
    INPUT_GOTO,
    INPUT_FILTER
};

extern vector_t *packets;
extern main_menu *menu;
bool selected[NUM_LAYERS];
bool numeric = true;
int hexmode = HEXMODE_NORMAL;
char load_filepath[MAXPATH + 1];
file_dialogue *load_dialogue;
file_dialogue *save_dialogue;
static enum input_mode input_mode;
static int view_mode = DECODED_VIEW;
static progress_dialogue *pd = NULL;
static bool decode_error = false;
static chtype original_line[MAXLINE];
static struct bpf_prog bpf;
static char bpf_filter[MAXLINE];
static WINDOW *status;

static bool check_line(main_screen *ms);
static void print_header(main_screen *ms);
static void print_selected_packet(main_screen *ms);
static void print_protocol_information(main_screen *ms, struct packet *p, int lineno);
static int print_lines(main_screen *ms, int from, int to, int y);
static void create_load_dialogue(void);
static void create_save_dialogue(void);
static bool read_show_progress(unsigned char *buffer, uint32_t n, struct timeval *t);
static void print_packets(main_screen *ms);
static void follow_tcp_stream(main_screen *ms);
static void show_selectionbar(main_screen *ms, WINDOW *win, int line, uint32_t attr);
static void remove_selectionbar(main_screen *ms, WINDOW *win, int line, uint32_t attr);
static void scroll_window(main_screen *ms);
static void add_elements(main_screen *ms, struct packet *p);
static void set_filter(main_screen *ms, int c);
static void clear_filter(main_screen *ms);
static void filter_packets(main_screen *ms);
static void handle_input_mode(main_screen *ms, const char *str);

/* Handles subwindow layout */
static void create_subwindow(main_screen *ms, int num_lines, int lineno);
static void delete_subwindow(main_screen *ms);
static bool inside_subwindow(main_screen *ms);
static void handle_selectionbar(main_screen *ms, int c);
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
    actionbar_add(s, "F6", "Load", ctx.capturing);
    actionbar_add(s, "F7", "View (dec)", false);
    actionbar_add(s, "F8", "Filter", false);
    actionbar_add(s, "F10", "Quit", false);
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
    memset(&ms->subwindow, 0, sizeof(ms->subwindow));
    nodelay(s->win, TRUE); /* input functions must be non-blocking */
    keypad(s->win, TRUE);
    scrollok(s->win, TRUE);
    ms->packet_ref = packets;
    getcwd(load_filepath, MAXPATH);
    ms->follow_stream = false;
    status = newwin(1, mx, my - 1, 0);
    add_actionbar_elems(s);
}

void main_screen_free(screen *s)
{
    main_screen *ms = (main_screen *) s;

    delwin(ms->subwindow.win);
    delwin(ms->header);
    delwin(ms->base.win);
    if (ms->lvw) {
        free_list_view(ms->lvw);
    }
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
            printnlw(ms->base.win, buf, strlen(buf), ms->outy, 0, ms->scrollx);
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
    if (!s->show_selectionbar && ctx.capturing && vector_size(ms->packet_ref) > my)
        print_packets(ms);
    else
        ms->outy = print_lines(ms, ms->base.top, ms->base.top + my, 0);
    if (s->show_selectionbar)
        show_selectionbar(ms, s->win, s->selectionbar - s->top, A_NORMAL);
    wnoutrefresh(s->win);
    if (ms->subwindow.win) {
        struct packet *p;

        wbkgd(ms->subwindow.win, get_theme_colour(BACKGROUND));
        p = vector_get_data(ms->packet_ref, ms->main_line.line_number + s->top);
        print_protocol_information(ms, p, ms->main_line.line_number + s->top);
        refresh_pad(ms, &ms->subwindow, 0, 0, false);
    }
    print_header(ms);
    wnoutrefresh(ms->header);
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

void main_screen_render(main_screen *ms, bool interactive_mode)
{
    if (vector_size(ms->packet_ref) == 0)
        return;

    int my = getmaxy(ms->base.win);

    if (vector_size(ms->packet_ref) < my) {
        ms->outy = print_lines(ms, 0, vector_size(ms->packet_ref), 0);
    } else {
        ms->outy = print_lines(ms, 0, my, 0);
    }
    ms->base.top = 0;
    if (interactive_mode) {
        ms->base.show_selectionbar = true;
        show_selectionbar(ms, ms->base.win, ms->base.selectionbar, A_NORMAL);
    }
    main_screen_refresh((screen *) ms);
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
        if (ms->subwindow.win && view_mode == HEXDUMP_VIEW) {
            struct packet *p;

            p = vector_get_data(ms->packet_ref, ms->main_line.line_number + s->top);
            print_protocol_information(ms, p, ms->main_line.line_number + s->top);
        }
        break;
    case 'n':
        numeric = !numeric;
        break;
    case KEY_UP:
        main_screen_handle_keyup(ms, my);
        break;
    case KEY_DOWN:
        main_screen_handle_keydown(ms, my);
        break;
    case KEY_LEFT:
        main_screen_scroll_column(ms, -NUM_COLS_SCROLL, my);
        break;
    case KEY_RIGHT:
        main_screen_scroll_column(ms, NUM_COLS_SCROLL, my);
        break;
    case KEY_ENTER:
    case '\n':
        if (s->show_selectionbar)
            print_selected_packet(ms);
        break;
    case KEY_ESC:
            if (ms->subwindow.win) {
                delete_subwindow(ms);
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
            ctx.capturing = true;
            print_header(ms);
            wnoutrefresh(s->win);
            wnoutrefresh(ms->header);
            actionbar_update(s, "F3", NULL, true);
            actionbar_update(s, "F4", NULL, false);
            actionbar_update(s, "F5", NULL, true);
            actionbar_update(s, "F6", NULL, true);
            doupdate();
            start_scan();
        }
        break;
    }
    case KEY_F(4):
        if (ctx.capturing) {
            if (!s->show_selectionbar) {
                main_screen_set_interactive(ms, true);
            }
            stop_scan();
            ctx.capturing = false;
            actionbar_update(s, "F3", NULL, false);
            actionbar_update(s, "F4", NULL, true);
            actionbar_update(s, "F5", NULL, !vector_size(ms->packet_ref));
            actionbar_update(s, "F6", NULL, false);
        }
        break;
    case KEY_F(5):
        if (!ctx.capturing && vector_size(ms->packet_ref) > 0) {
            create_save_dialogue();
        }
        break;
    case KEY_F(6):
        if (!ctx.capturing) {
            create_load_dialogue();
        }
        break;
    case KEY_F(7):
        view_mode = (view_mode + 1) % NUM_VIEWS;
        if (ms->subwindow.win) {
            struct packet *p;

            ms->base.selectionbar = ms->main_line.line_number + s->top - ms->scrolly;
            p = vector_get_data(ms->packet_ref, ms->main_line.line_number + s->top);
            if (view_mode == DECODED_VIEW) {
                add_elements(ms, p);
            }
            print_protocol_information(ms, p, ms->main_line.line_number + s->top);
        }
        actionbar_update(s, "F7", (view_mode == DECODED_VIEW) ? "View (dec)" :
                         "View (hex)", false);
        break;
    case 'e':
    case KEY_F(8):
        input_mode = (input_mode == INPUT_FILTER) ? INPUT_NONE : INPUT_FILTER;
        handle_input_mode(ms, "Filter: ");
        break;
    default:
        ungetch(c);
        screen_get_input(s);
        break;
    }
}

void create_load_dialogue(void)
{
    if (!load_dialogue) {
        load_dialogue = file_dialogue_create(" Load capture file ", FS_LOAD, load_filepath,
                                  main_screen_load_handle_ok, main_screen_load_handle_cancel);
        push_screen((screen *) load_dialogue);
    }
}

void create_save_dialogue(void)
{
    if (!save_dialogue) {
        save_dialogue = file_dialogue_create(" Save as pcap ", FS_SAVE, load_filepath,
                                             main_screen_save_handle_ok, main_screen_save_handle_cancel);
        push_screen((screen *) save_dialogue);
    }
}

void main_screen_load_handle_ok(void *file)
{
    enum file_error err;
    FILE *fp;

    /* don't allow filenames containing ".." */
    if (strstr((const char *) file, "..")) {
        create_file_error_dialogue(ACCESS_ERROR, create_load_dialogue);
    } else if ((fp = open_file((const char *) file, "r", &err)) == NULL) {
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
        err = read_file(fp, read_show_progress);
        if (err == NO_ERROR) {
            int i;

            main_screen_clear(ms);
            strcpy(ctx.filename, (const char *) file);
            i = string_find_last(ctx.filename, '/');
            if (i > 0 && i < MAXPATH) {
                strncpy(load_filepath, ctx.filename, i);
                load_filepath[i] = '\0';
            }
            pop_screen();
            SCREEN_FREE((screen *) pd);
            print_file();
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

void main_screen_save_handle_ok(void *file)
{
    enum file_error err;
    FILE *fp;

    if ((fp = open_file((const char *) file, "w", &err)) == NULL) {
        create_file_error_dialogue(err, create_save_dialogue);
    } else {
        char title[MAXLINE];
        main_screen *ms = (main_screen *) screen_cache_get(MAIN_SCREEN);

        get_file_part(file);
        snprintf(title, MAXLINE, " Saving %s ", (char *) file);
        pd = progress_dialogue_create(title, total_bytes);
        push_screen((screen *) pd);
        write_pcap(fp, ms->packet_ref, main_screen_write_show_progress);
        pop_screen();
        SCREEN_FREE((screen *) pd);
        fclose(fp);
    }
    SCREEN_FREE((screen *) save_dialogue);
    save_dialogue = NULL;
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

bool read_show_progress(unsigned char *buffer, uint32_t n, struct timeval *t)
{
    struct packet *p;
    main_screen *ms = (main_screen *) screen_cache_get(MAIN_SCREEN);

    if (!decode_packet(buffer, n, &p)) {
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

void show_selectionbar(main_screen *ms UNUSED, WINDOW *win, int line, uint32_t attr)
{
    mvwinchstr(win, line, 0, original_line);
    mvwchgat(win, line, 0, -1, attr, PAIR_NUMBER(get_theme_colour(SELECTIONBAR)), NULL);
}

void remove_selectionbar(main_screen *ms, WINDOW *win, int line, uint32_t attr)
{
    mvwchgat(win, line, 0, -1, attr, PAIR_NUMBER(get_theme_colour(BACKGROUND)), NULL);
    if (inside_subwindow(ms) && !ms->lvw) { // TODO: fix this
        int i = 0;
        int mx = getmaxx(win);
        int c;

        while (original_line[i] == 0 && i < mx)
            i++;
        c = i;
        while (original_line[c] != 0 && c < mx - 1)
            mvwaddch(win, line, c, original_line[c++]);
    }
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
    if (ctx.filename[0]) {
        strncpy(file, ctx.filename, MAXPATH - 1);
        printat(ms->header, y, 0, txtcol, "Filename");
        wprintw(ms->header, ": %s", get_file_part(file));
    } else {
        printat(ms->header, y, 0, txtcol, "Device");
        wprintw(ms->header, ": %s", ctx.device);
    }
    printat(ms->header, y, maxx / 2, txtcol, "Display filter");
    if (bpf.size != 0)
        wprintw(ms->header, ": %s", bpf_filter);
    else
        wprintw(ms->header, ": None");
    inet_ntop(AF_INET, &ctx.local_addr->sin_addr, addr, sizeof(addr));
    printat(ms->header, ++y, 0, txtcol, "IPv4 address");
    wprintw(ms->header, ": %s", addr);
    printat(ms->header, y, maxx / 2, txtcol, "Follow stream");
    if (ms->follow_stream)
        wprintw(ms->header, ": %u", ((conversation_screen *) ms)->stream->num);
    else
        wprintw(ms->header, ": None");
    HW_ADDR_NTOP(mac, ctx.mac);
    printat(ms->header, ++y, 0, txtcol, "MAC");
    wprintw(ms->header, ": %s", mac);
    y += 2;
    for (unsigned int i = 0; i < ARRAY_SIZE(main_header); i++) {
        mvwprintw(ms->header, y, x, main_header[i].txt);
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
        mvwprintw(status, 0, 0, str);
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
        if ((ms->subwindow.win && num > ms->subwindow.num_lines + vector_size(ms->packet_ref)) ||
            (!ms->subwindow.win && num > vector_size(ms->packet_ref))) {
            return;
        }

        int my;

        my = getmaxy(ms->base.win);
        if (num >= ms->base.top && num < ms->base.top + my) {
            remove_selectionbar(ms, ms->base.win, ms->base.selectionbar, A_NORMAL);
            if (ms->subwindow.win && num > ms->base.top + ms->subwindow.top) {
                ms->base.selectionbar = num - 1 + ms->subwindow.num_lines;
            } else {
                ms->base.selectionbar = num - 1;
            }
            show_selectionbar(ms, ms->base.win, ms->base.selectionbar, A_NORMAL);
        } else {
            werase(ms->base.win);
            remove_selectionbar(ms, ms->base.win, ms->base.selectionbar, A_NORMAL);
            if (num + my - 1 > vector_size(ms->packet_ref)) {
                print_lines(ms, vector_size(ms->packet_ref) - my, vector_size(ms->packet_ref), 0);
                ms->base.top = vector_size(ms->packet_ref) - my;
                ms->base.selectionbar = num - 1;
                show_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
            } else {
                print_lines(ms, num - 1, num + my - 1, 0);
                ms->base.selectionbar = ms->base.top = num - 1;
                show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
            }
        }
        wrefresh(ms->base.win);
        curs_set(0);
        werase(status);
        input_mode = INPUT_NONE;
        num = 0;
        actionbar_refresh(actionbar, (screen *) ms);
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
    int my = getmaxy(ms->base.win);

    werase(ms->base.win);
    print_lines(ms, 0, my, 0);
    ms->base.selectionbar = 0;
    ms->base.top = 0;
    show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
    wrefresh(ms->base.win);
}

void main_screen_goto_end(main_screen *ms)
{
    int my = getmaxy(ms->base.win);

    if (ms->outy >= my) {
        print_packets(ms);
        remove_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
        ms->base.selectionbar = vector_size(ms->packet_ref) - 1;
        show_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
        wrefresh(ms->base.win);
    }
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
        }
        if (ms->base.show_selectionbar && vector_size(ms->packet_ref) > 0)
            show_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
        print_header(ms);
        wnoutrefresh(ms->header);
        wnoutrefresh(ms->base.win);
        doupdate();
        wbkgd(status, get_theme_colour(BACKGROUND));
        numc = 0;
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
        int my = getmaxy(ms->base.win);

        free(bpf.bytecode);
        bpf.size = 0;
        vector_free(ms->packet_ref, NULL);
        ms->packet_ref = packets;
        werase(ms->base.win);
        if (ctx.capturing && vector_size(packets) >= my) {
            print_packets(ms);
        } else {
            ms->outy = print_lines(ms, 0, getmaxy(ms->base.win), 0);
            ms->base.top = 0;
            ms->base.selectionbar = 0;
        }
    }
    memset(bpf_filter, 0, sizeof(bpf_filter));
    input_mode = INPUT_NONE;
    werase(status);
    actionbar_refresh(actionbar, (screen *) ms);
}

void filter_packets(main_screen *ms)
{
    int my;

    ms->packet_ref = vector_init(PACKET_TABLE_SIZE);
    for (int i = 0; i < vector_size(packets); i++) {
        struct packet *p = vector_get_data(packets, i);

        if (bpf_run_filter(bpf, p->buf, p->len) != 0)
            vector_push_back(ms->packet_ref, p);
    }
    input_mode = INPUT_NONE;
    werase(status);
    actionbar_refresh(actionbar, (screen *) ms);
    werase(ms->base.win);
    my = getmaxy(ms->base.win);
    if (!ms->base.show_selectionbar && ctx.capturing &&
        vector_size(ms->packet_ref) > my) {
        print_packets(ms);
    } else {
        ms->outy = print_lines(ms, 0, my, 0);
        ms->base.top = 0;
        ms->base.selectionbar = 0;
    }
}

void print_packets(main_screen *ms)
{
    int c = vector_size(ms->packet_ref) - 1;
    int my = getmaxy(ms->base.win);

    werase(ms->base.win);

    /* print the new lines stored in vector from bottom to top of screen */
    for (int i = my - 1; i >= 0; i--, c--) {
        struct packet *p;
        char buffer[MAXLINE];

        p = vector_get_data(ms->packet_ref, c);
        write_to_buf(buffer, MAXLINE, p);
        printnlw(ms->base.win, buffer, strlen(buffer), i, 0, ms->scrollx);
    }
    ms->base.top = c + 1;
    ms->outy = my;
}

/*
 * Checks if there still are lines to highlight when moving the selection bar
 * down. Returns true if that's the case.
 */
bool check_line(main_screen *ms)
{
    int num_lines = 0;

    if (ms->subwindow.win) {
        num_lines += ms->subwindow.num_lines;
    }
    if (ms->base.selectionbar + ms->scrolly < vector_size(ms->packet_ref) + num_lines - 1) {
        return true;
    }
    return false;
}

void main_screen_scroll_column(main_screen *ms, int scrollx, int num_lines)
{
    if ((scrollx < 0 && ms->scrollx) || scrollx > 0) {
        werase(ms->base.win);
        ms->scrollx += scrollx;
        if (ms->subwindow.win) {
            ms->outy = print_lines(ms, ms->base.top + ms->scrolly, ms->base.top + num_lines, 0) + ms->scrolly;
            if (!inside_subwindow(ms)) {
                show_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
            }
            wnoutrefresh(ms->base.win);
            refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, false);
            doupdate();
        } else {
            ms->outy = print_lines(ms, ms->base.top, ms->base.top + num_lines, 0);
            show_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
            wrefresh(ms->base.win);
        }
    }
}

void main_screen_handle_keyup(main_screen *ms, int num_lines)
{
    if (!ms->base.show_selectionbar) {
        main_screen_set_interactive(ms, true);
    }
    if (!ms->lvw && ms->subwindow.win && ms->subwindow.num_lines > num_lines) {
        if (ms->subwindow.num_lines + ms->subwindow.top <= ms->subwindow.num_lines)
            refresh_pad(ms, &ms->subwindow, 1, ms->scrollx, true);
        return;
    }

    /* scroll screen if the selection bar is at the top */
    if (ms->base.top > 0 && ms->base.selectionbar == ms->base.top) {
        struct packet *p;
        int subline;

        ms->base.selectionbar--;
        if (ms->subwindow.win && (ms->base.selectionbar >= ms->subwindow.top + ms->base.top + ms->subwindow.num_lines)) {
            p = vector_get_data(ms->packet_ref, ms->base.selectionbar - ms->subwindow.num_lines + ms->scrolly);
        } else {
            p = vector_get_data(ms->packet_ref, ms->base.selectionbar + ms->scrolly);
        }
        ms->base.top--;
        wscrl(ms->base.win, -1);
        subline = ms->base.selectionbar - ms->base.top - ms->subwindow.top;
        if (p && !(ms->subwindow.win && subline > 0 && subline < ms->subwindow.num_lines)) {
            char line[MAXLINE];

            write_to_buf(line, MAXLINE, p);
            printnlw(ms->base.win, line, strlen(line), 0, 0, ms->scrollx);
            remove_selectionbar(ms, ms->base.win, 1, A_NORMAL);
            show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
            wnoutrefresh(ms->base.win);
        }
        if (ms->subwindow.win) {
            if (inside_subwindow(ms)) {
                wnoutrefresh(ms->base.win);
            }
            handle_selectionbar(ms, KEY_UP);
            refresh_pad(ms, &ms->subwindow, 1, ms->scrollx, false);
        }
        doupdate();
    } else if (ms->base.selectionbar > 0) {
        int screen_line = ms->base.selectionbar - ms->base.top;

        if (ms->subwindow.win && screen_line >= ms->subwindow.top &&
            screen_line <= ms->subwindow.top + ms->subwindow.num_lines) {
            handle_selectionbar(ms, KEY_UP);
            refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, true);
        } else {
            remove_selectionbar(ms, ms->base.win, screen_line, A_NORMAL);
            show_selectionbar(ms, ms->base.win, screen_line - 1, A_NORMAL);
        }
        ms->base.selectionbar--;
        wrefresh(ms->base.win);
    }
}

void main_screen_handle_keydown(main_screen *ms, int num_lines)
{
    if (!check_line(ms))
        return;
    if (!ms->base.show_selectionbar)
        main_screen_set_interactive(ms, true);
    if (!ms->lvw && ms->subwindow.win && ms->subwindow.num_lines > num_lines) {
        if (ms->subwindow.num_lines + ms->subwindow.top >= num_lines) {
            if (!ms->subwindow.scroll)
                ms->subwindow.scroll = true;
            refresh_pad(ms, &ms->subwindow, -1, ms->scrollx, true);
        }
        return;
    }

    /* scroll screen if the selection bar is at the bottom */
    if (ms->base.selectionbar - ms->base.top == num_lines - 1) {
        struct packet *p;
        int subline;

        if (ms->subwindow.win && (ms->base.selectionbar + 1 >= ms->subwindow.top + ms->base.top + ms->subwindow.num_lines)) {
            p = vector_get_data(ms->packet_ref, ms->base.selectionbar + 1 - ms->subwindow.num_lines + ms->scrolly);
        } else {
            p = vector_get_data(ms->packet_ref, ms->base.selectionbar + 1 + ms->scrolly);
        }
        ms->base.top++;
        ms->base.selectionbar++;
        wscrl(ms->base.win, 1);
        subline = ms->base.selectionbar - ms->base.top - ms->subwindow.top + 1;
        if (p && !(ms->subwindow.win && subline > 0 && subline < ms->subwindow.num_lines)) {
            char line[MAXLINE];

            write_to_buf(line, MAXLINE, p);
            printnlw(ms->base.win, line, strlen(line), num_lines - 1, 0, ms->scrollx);
            remove_selectionbar(ms, ms->base.win, num_lines - 2, A_NORMAL);
            show_selectionbar(ms, ms->base.win, num_lines - 1, A_NORMAL);
            wnoutrefresh(ms->base.win);
        }
        if (ms->subwindow.win) {
            if (inside_subwindow(ms)) {
                wnoutrefresh(ms->base.win);
            }
            handle_selectionbar(ms, KEY_DOWN);
            refresh_pad(ms, &ms->subwindow, -1, ms->scrollx, false);
        }
        doupdate();
    } else {
        int screen_line = ms->base.selectionbar - ms->base.top;

        if (ms->subwindow.win && screen_line + 1 >= ms->subwindow.top &&
            screen_line + 1 <= ms->subwindow.top + ms->subwindow.num_lines) {
            handle_selectionbar(ms, KEY_DOWN);
            refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, true);
        } else {
            remove_selectionbar(ms, ms->base.win, screen_line, A_NORMAL);
            show_selectionbar(ms, ms->base.win, screen_line + 1, A_NORMAL);
        }
        ms->base.selectionbar++;
        wrefresh(ms->base.win);
    }
}

void main_screen_scroll_page(main_screen *ms, int num_lines)
{
    if (!ms->base.show_selectionbar) {
        main_screen_set_interactive(ms, true);
    }
    if (num_lines > 0) { /* scroll page down */
        if (ms->subwindow.win && ms->subwindow.num_lines > num_lines) {
            if (ms->subwindow.num_lines + ms->subwindow.top >= num_lines) {
                int scroll;

                if (!ms->lvw && !ms->subwindow.scroll)
                    ms->subwindow.scroll = true;
                scroll = (ms->subwindow.num_lines + (ms->subwindow.top - num_lines) < num_lines) ?
                    ms->subwindow.num_lines + (ms->subwindow.top - num_lines) : num_lines;
                if (ms->lvw) {
                    ms->base.top += scroll;
                    ms->base.selectionbar += scroll;
                }
                refresh_pad(ms, &ms->subwindow, -scroll, ms->scrollx, true);
            }
            return;
        }
        if (vector_size(ms->packet_ref) <= num_lines) {
            remove_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
            if (ms->subwindow.win) {
                ms->base.selectionbar = ms->subwindow.num_lines + vector_size(ms->packet_ref) - 1;
            } else {
                ms->base.selectionbar = vector_size(ms->packet_ref) - 1;
            }
            show_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
            wrefresh(ms->base.win);
        } else {
            int bottom = ms->base.top + num_lines - 1;

            remove_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
            ms->base.selectionbar += num_lines;
            if (bottom + num_lines > vector_size(ms->packet_ref) - 1) {
                int scroll = vector_size(ms->packet_ref) - bottom - 1;

                wscrl(ms->base.win, scroll);
                ms->base.top += scroll;
                if (ms->base.selectionbar >= vector_size(ms->packet_ref)) {
                    ms->base.selectionbar = vector_size(ms->packet_ref) - 1;
                }
                print_lines(ms, bottom + 1, vector_size(ms->packet_ref), vector_size(ms->packet_ref) - scroll - ms->base.top);
                show_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
                wnoutrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, -scroll, ms->scrollx, false);
                }
                doupdate();
            } else {
                ms->base.top += num_lines;
                wscrl(ms->base.win, num_lines);
                print_lines(ms, ms->base.top, ms->base.top + num_lines, 0);
                show_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
                wnoutrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, -num_lines, ms->scrollx, false);
                }
                doupdate();
            }
        }
    } else { /* scroll page up */
        if (ms->subwindow.win && ms->subwindow.num_lines > abs(num_lines)) {
            if (ms->subwindow.num_lines + ms->subwindow.top <= ms->subwindow.num_lines) {
                int scroll;

                scroll = (num_lines < ms->subwindow.top) ? ms->subwindow.top - 1 : num_lines;
                if (ms->lvw) {
                    ms->base.top += scroll;
                    ms->base.selectionbar += scroll;
                }
                refresh_pad(ms, &ms->subwindow, -scroll, ms->scrollx, true);
            }
            return;
        }
        if (vector_size(ms->packet_ref) <= abs(num_lines) || ms->base.top == 0) {
            remove_selectionbar(ms, ms->base.win, ms->base.selectionbar, A_NORMAL);
            ms->base.selectionbar = 0;
            show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
            wrefresh(ms->base.win);
        } else {
            remove_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
            ms->base.selectionbar += num_lines;
            if (ms->base.top + num_lines < 0) {
                wscrl(ms->base.win, -ms->base.top);
                if (ms->base.selectionbar < 0) {
                    ms->base.selectionbar = 0;
                }
                print_lines(ms, 0, -num_lines, 0);
                show_selectionbar(ms, ms->base.win, ms->base.selectionbar, A_NORMAL);
                wnoutrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, ms->base.top, ms->scrollx, false);
                }
                doupdate();
                ms->base.top = 0;
            } else {
                wscrl(ms->base.win, num_lines);
                ms->base.top += num_lines;
                print_lines(ms, ms->base.top, ms->base.top - num_lines, 0);
                show_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
                wnoutrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, -num_lines, ms->scrollx, false);
                }
                doupdate();
            }
        }
    }
}

void main_screen_set_interactive(main_screen *ms, bool interactive_mode)
{
    if (!vector_size(ms->packet_ref)) return;

    if (interactive_mode) {
        ms->base.show_selectionbar = true;
        ms->base.selectionbar = ms->base.top;
        show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
        wrefresh(ms->base.win);
    } else {
        int my;

        my = getmaxy(ms->base.win);
        if (ms->subwindow.win) {
            delete_subwindow(ms);
            ms->main_line.selected = false;
        }
        if (ms->outy >= my && ctx.capturing) {
            print_packets(ms);
        } else {
            remove_selectionbar(ms, ms->base.win, ms->base.selectionbar - ms->base.top, A_NORMAL);
        }
        ms->base.show_selectionbar = false;
        wrefresh(ms->base.win);
    }
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

        if (ms->subwindow.win && line > ms->subwindow.lineno &&
            line <= ms->subwindow.lineno + ms->subwindow.num_lines) {
            y++;
        } else {
            p = vector_get_data(ms->packet_ref, from);
            if (!p) break;
            write_to_buf(buffer, MAXLINE, p);
            if (ms->scrollx) {
                int n = strlen(buffer);

                if (ms->scrollx < n) {
                    printnlw(ms->base.win, buffer, n, y++, 0, ms->scrollx);
                } else {
                    y++;
                }
            } else {
                printnlw(ms->base.win, buffer, strlen(buffer), y++, 0, ms->scrollx);
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
            if (!ms->lvw) return;

            /* update the selection status of the selectable subwindow line */
            screen_line = ms->base.selectionbar - ms->base.top;
            subline = screen_line - ms->subwindow.top;
            data = LV_GET_DATA(ms->lvw, subline);
            LV_SET_EXPANDED(ms->lvw, subline, !LV_GET_EXPANDED(ms->lvw, subline));
            if (data >= 0 && data < NUM_LAYERS) {
                selected[data] = LV_GET_EXPANDED(ms->lvw, subline);
            }
            p = vector_get_data(ms->packet_ref, prev_selection);
            print_protocol_information(ms, p, prev_selection);
            return;
        }
    }
    screen_line = ms->base.selectionbar + ms->scrolly - ms->base.top;
    if (screen_line == ms->main_line.line_number) {
        ms->main_line.selected = !ms->main_line.selected;
    } else {
        ms->main_line.selected = true;

        /* the index to the selected line needs to be adjusted in case of an
           open subwindow */
        if (ms->subwindow.win && subwindow_on_screen(ms) &&
            screen_line > ms->subwindow.top + ms->scrolly) {
            ms->main_line.line_number = screen_line - ms->subwindow.num_lines;
            ms->base.selectionbar -= ms->subwindow.num_lines;
        } else {
            ms->main_line.line_number = screen_line;
        }
    }
    if (ms->main_line.selected) {
        p = vector_get_data(ms->packet_ref, ms->base.selectionbar + ms->scrolly);
        if (view_mode == DECODED_VIEW) {
            add_elements(ms, p);
        }
        print_protocol_information(ms, p, ms->base.selectionbar + ms->scrolly);
    } else {
        delete_subwindow(ms);
    }
    prev_selection = ms->base.selectionbar + ms->scrolly;
}

void add_elements(main_screen *ms, struct packet *p)
{
    list_view_header *header;
    struct protocol_info *pinfo;
    struct eth_info *eth;
    struct packet_data *pdata;
    int i = 0;
    int idx = 0;

    if (ms->lvw) {
        free_list_view(ms->lvw);
    }
    ms->lvw = create_list_view();
    pdata = p->root;
    eth = pdata->data;

    /* inspect packet and add packet headers as elements to the list view */
    if (eth->ethertype <= ETH_802_3_MAX)
        header = LV_ADD_HEADER(ms->lvw, "Ethernet 802.3", selected[UI_LAYER1], UI_LAYER1);
    else
        header = LV_ADD_HEADER(ms->lvw, "Ethernet II", selected[UI_LAYER1], UI_LAYER1);
    add_ethernet_information(ms->lvw, header, p);
    idx += pdata->len;
    while (pdata->next) {
        pinfo = get_protocol(pdata->id);
        pdata = pdata->next;
        i++;
        idx += pdata->len;
        if (pinfo && i < NUM_LAYERS) {
            header = LV_ADD_HEADER(ms->lvw, pinfo->long_name, selected[i], i);
            pinfo->add_pdu(ms->lvw, header, pdata);
        }
    }
    if (p->perr != NO_ERR && (int) p->len - idx > 0) {
        header = LV_ADD_HEADER(ms->lvw, "Data", selected[i+1], i + 1);
        add_hexdump(ms->lvw, header, hexmode, p->buf + idx, p->len - idx);
    }
}

void print_protocol_information(main_screen *ms, struct packet *p, int lineno)
{
    /* delete old subwindow */
    if (ms->subwindow.win) {
        delete_subwindow(ms);
    }

    if (view_mode == DECODED_VIEW) {
        int subline;

        create_subwindow(ms, ms->lvw->size + 1, lineno);
        LV_RENDER(ms->lvw, ms->subwindow.win);
        subline = ms->base.selectionbar - ms->base.top - ms->subwindow.top;
        if (inside_subwindow(ms)) {
            show_selectionbar(ms, ms->subwindow.win, subline, LV_GET_ATTR(ms->lvw, subline));
        }
        refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, true);
    } else {
        int subline;
        int num_lines = (hexmode == HEXMODE_NORMAL) ? p->len / 16 + 3 : p->len / 64 + 3;

        if (ms->lvw) {
            free_list_view(ms->lvw);
            ms->lvw = NULL;
        }
        create_subwindow(ms, num_lines, lineno);
        add_winhexdump(ms->subwindow.win, 0, 2, hexmode, p);
        subline = ms->base.selectionbar - ms->base.top - ms->subwindow.top;
        if (inside_subwindow(ms)) {
            show_selectionbar(ms, ms->subwindow.win, subline, A_NORMAL);
        }
        refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, true);
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
        wscrl(ms->base.win, ms->scrolly);
        start_line -= ms->scrolly;
        ms->base.selectionbar -= ms->scrolly;
    }

    /* make space for protocol specific information */
    ms->subwindow.win = newpad(num_lines, mx);
    wbkgd(ms->subwindow.win, get_theme_colour(BACKGROUND));
    scrollok(ms->subwindow.win, TRUE);
    ms->subwindow.top = start_line + 1;
    ms->subwindow.num_lines = num_lines;
    ms->subwindow.lineno = lineno;
    ms->subwindow.scroll = false;
    wmove(ms->base.win, start_line + 1, 0);
    wclrtobot(ms->base.win); /* clear everything below selection bar */
    ms->outy = start_line + 1;
    if (!ms->scrolly) {
        ms->outy += print_lines(ms, c, ms->base.top + my, ms->outy);
    } else {
        ms->outy += num_lines;
    }
    wrefresh(ms->base.win);
}

void delete_subwindow(main_screen *ms)
{
    int my;
    int screen_line;

    my = getmaxy(ms->base.win);
    screen_line = ms->base.selectionbar - ms->base.top;
    delwin(ms->subwindow.win);
    ms->subwindow.win = NULL;
    ms->subwindow.num_lines = 0;
    werase(ms->base.win);

    /*
     * Print the entire screen. This can be optimized to just print the lines
     * that are below the selected line
     */
    ms->outy = print_lines(ms, ms->base.top, ms->base.top + my, 0);

    if (ms->scrolly) {
        screen_line += ms->scrolly;
        ms->base.selectionbar += ms->scrolly;
        ms->scrolly = 0;
    }
    show_selectionbar(ms, ms->base.win, screen_line, A_NORMAL);
    wrefresh(ms->base.win);
}

/* Returns whether the selection line is inside the subwindow or not */
bool inside_subwindow(main_screen *ms)
{
    int subline = ms->base.selectionbar - ms->base.top - ms->subwindow.top;

    return ms->subwindow.win && subline >= 0 && subline < ms->subwindow.num_lines;
}

/* Returns whether the subwindow is shown on screen or not */
bool subwindow_on_screen(main_screen *ms)
{
    int my;

    my = getmaxy(ms->base.win);
    return ms->subwindow.lineno >= ms->base.top && ms->subwindow.lineno <= ms->base.top + my;
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
    if (ms->lvw)
        ms->main_line.line_number += scrolly;
    if (pad->top <= 0) {
        if (!ms->lvw && pad->top == 0 && scrolly == -1)
            pad->top--;
        if (update) {
            prefresh(pad->win, abs(pad->top), minx, ms->subwindow.scroll ?
                     GET_SCRY(0) + 1 : GET_SCRY(0) , 0, GET_SCRY(my) - 1, mx);
        } else {
            pnoutrefresh(pad->win, abs(pad->top), minx, ms->subwindow.scroll ?
                         GET_SCRY(0) + 1 : GET_SCRY(0), 0, GET_SCRY(my) - 1, mx);
        }
    } else {
        if (update) {
            prefresh(pad->win, 0, minx, GET_SCRY(pad->top), 0, GET_SCRY(my) - 1, mx);
        } else {
            pnoutrefresh(pad->win, 0, minx, GET_SCRY(pad->top), 0, GET_SCRY(my) - 1, mx);
        }
    }
}

void handle_selectionbar(main_screen *ms, int c)
{
    int screen_line = ms->base.selectionbar - ms->base.top;
    int subline = screen_line - ms->subwindow.top;

    if (c == KEY_UP) {
        if (screen_line == ms->subwindow.top + ms->subwindow.num_lines) {
            remove_selectionbar(ms, ms->base.win, screen_line, A_NORMAL);
        } else {
            remove_selectionbar(ms, ms->subwindow.win, subline, ms->lvw ? LV_GET_ATTR(ms->lvw, subline) : A_NORMAL);
        }
        if (subline == 0) {
            show_selectionbar(ms, ms->base.win, screen_line - 1, A_NORMAL);
        } else {
            show_selectionbar(ms, ms->subwindow.win, subline - 1, ms->lvw ? LV_GET_ATTR(ms->lvw, subline - 1) : A_NORMAL);
        }
    } else if (c == KEY_DOWN) {
        if (subline == -1) {
            remove_selectionbar(ms, ms->base.win, screen_line, A_NORMAL);
        } else {
            remove_selectionbar(ms, ms->subwindow.win, subline, ms->lvw ? LV_GET_ATTR(ms->lvw, subline) : A_NORMAL);
        }
        if (screen_line + 1 == ms->subwindow.top + ms->subwindow.num_lines) {
            show_selectionbar(ms, ms->base.win, screen_line + 1, A_NORMAL);
        } else {
            show_selectionbar(ms, ms->subwindow.win, subline + 1, ms->lvw ? LV_GET_ATTR(ms->lvw, subline + 1) : A_NORMAL);
        }
    }
}

static void follow_tcp_stream(main_screen *ms)
{
    hashmap_t *connections = tcp_analyzer_get_sessions();
    struct packet *p = vector_get_data(ms->packet_ref, ms->base.selectionbar);
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
