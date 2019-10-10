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
#include "../util.h"
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

#define HEADER_HEIGHT 5
#define NUM_COLS_SCROLL 4
#define TCP_PAGE_SIZE 1000

/* Get the y screen coordinate. The argument is the main_screen coordinate */
#define GET_SCRY(y) ((y) + HEADER_HEIGHT)

enum views {
    DECODED_VIEW,
    HEXDUMP_VIEW,
    NUM_VIEWS
};

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
extern WINDOW *status;
extern main_menu *menu;
bool selected[NUM_LAYERS];
bool numeric = true;
int hexmode = HEXMODE_NORMAL;
static bool interactive = false;
static bool input_mode = false;
static int view_mode = DECODED_VIEW;
static label_dialogue *ld = NULL;
static file_dialogue *fd = NULL;
static file_dialogue *sd = NULL;
static progress_dialogue *pd = NULL;
static char load_filepath[MAXPATH + 1];
static bool decode_error = false;
static chtype original_line[MAXLINE];
static vector_t *packet_ref;
static bool follow_stream = false;
static struct tcp_connection_v4 *stream;
static enum follow_tcp_mode tcp_mode = NORMAL;
static main_screen *ms_ref;
static struct tcp_page tcp_page;

static void main_screen_init(screen *s);
static void main_screen_refresh(screen *s);
static void main_screen_clear(main_screen *ms);
static void main_screen_get_input(screen *s);
static bool check_line(main_screen *ms);
static void handle_keydown(main_screen *ms, int num_lines);
static void handle_keyup(main_screen *ms, int num_lines);
static void scroll_page(main_screen *ms, int num_lines);
static void scroll_column(main_screen *ms, int scrollx, int num_lines);
static void scroll_window(main_screen *ms);
static int print_lines(main_screen *ms, int from, int to, int y);
static void print_header(main_screen *ms);
static void print_status();
static void print_selected_packet(main_screen *ms);
static void print_protocol_information(main_screen *ms, struct packet *p, int lineno);
static void goto_line(main_screen *ms, int c);
static void goto_end(main_screen *ms);
static void goto_home(main_screen *ms);
static void create_load_dialogue();
static void create_save_dialogue();
static void create_file_error_dialogue(enum file_error err, void (*callback)());
static void load_handle_ok(void *file);
static void load_handle_cancel(void *);
static void save_handle_ok(void *file);
static void save_handle_cancel(void *);
static void handle_file_error(void *callback);
static void show_selectionbar(main_screen *ms, WINDOW *win, int line, uint32_t attr);
static void remove_selectionbar(main_screen *ms, WINDOW *win, int line, uint32_t attr);
static bool read_show_progress(unsigned char *buffer, uint32_t n, struct timeval *t);
static void write_show_progress(int i);
static void follow_tcp_stream(main_screen *ms, bool follow);
static void add_packet(struct tcp_connection_v4 *conn, bool new_connection);
static void change_tcp_mode(main_screen *ms);
static void buffer_tcppage(main_screen *ms, int (*buffer_fn)
                          (unsigned char *buf, int len, struct tcp_page_attr *attr, int pidx, int mx));
static int buffer_ascii(unsigned char *buf, int len, struct tcp_page_attr *attr, int pidx, int mx);
static int buffer_raw(unsigned char *buf, int len, struct tcp_page_attr *attr, int pidx, int mx);
static void print_tcppage(main_screen *ms);
static void free_tcp_attr(void *arg);
static void print_packets(main_screen *ms);

/* Handles subwindow layout */
static void create_subwindow(main_screen *ms, int num_lines, int lineno);
static void delete_subwindow(main_screen *ms);
static bool inside_subwindow(main_screen *ms);
static void add_elements(main_screen *ms, struct packet *p);
static void add_transport_elements(main_screen *ms, struct packet *p);
static void add_app_elements(main_screen *ms, struct packet *p, struct application_info *info, uint16_t len);
static void handle_selectionbar(main_screen *ms, int c);
static void refresh_pad(main_screen *ms, struct subwin_info *pad, int scrolly, int minx, bool update);
static bool subwindow_on_screen(main_screen *ms);

static screen_operations msop = {
    .screen_init = main_screen_init,
    .screen_free = main_screen_free,
    .screen_refresh = main_screen_refresh,
    .screen_get_input = main_screen_get_input
};

static screen_header header[] = {
    { "Number", NUM_WIDTH },
    { "Time", TIME_WIDTH },
    { "Source", ADDR_WIDTH },
    { "Destination", ADDR_WIDTH },
    { "Protocol", PROT_WIDTH },
    { "Info", 0 }
};

main_screen *main_screen_create()
{
    main_screen *ms;

    ms = malloc(sizeof(main_screen));
    ms->base.op = &msop;
    main_screen_init((screen *) ms);
    ms_ref = ms;
    return ms;
}

void main_screen_init(screen *s)
{
    main_screen *ms = (main_screen *) s;
    int my, mx;

    getmaxyx(stdscr, my, mx);
    ms->outy = 0;
    ms->selectionbar = 0;
    ms->top = 0;
    ms->scrolly = 0;
    ms->scrollx = 0;
    ms->lvw = NULL;
    ms->header = newwin(HEADER_HEIGHT, mx, 0, 0);
    ms->base.win = newwin(my - HEADER_HEIGHT - STATUS_HEIGHT, mx, HEADER_HEIGHT, 0);
    ms->base.focus = false;
    memset(&ms->subwindow, 0, sizeof(ms->subwindow));
    nodelay(ms->base.win, TRUE); /* input functions must be non-blocking */
    keypad(ms->base.win, TRUE);
    scrollok(ms->base.win, TRUE);
    packet_ref = packets;
    memset(&tcp_page, 0, sizeof(struct tcp_page));
    tcp_page.buf = vector_init(TCP_PAGE_SIZE);
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
    free(ms);
}

void main_screen_update(main_screen *ms, char *buf)
{
    int my;

    if (ms->base.focus) {
        my = getmaxy(ms->base.win);
        if (!interactive || (interactive && ms->outy < my)) {
            scroll_window(ms);
            printnlw(ms->base.win, buf, strlen(buf), ms->outy, 0, ms->scrollx);
            ms->outy++;
            wrefresh(ms->base.win);
        }
    }
}

void main_screen_clear(main_screen *ms)
{
    main_screen_set_interactive(ms, false);
    werase(ms->header);
    werase(ms->base.win);
    ms->selectionbar = 0;
    ms->top = 0;
    ms->outy = 0;
}

void main_screen_refresh(screen *s)
{
    int my;
    main_screen *ms;
    int c;

    ms = (main_screen *) s;
    my = getmaxy(ms->base.win);
    wbkgd(ms->base.win, get_theme_colour(BACKGROUND));
    wbkgd(ms->header, get_theme_colour(BACKGROUND));
    touchwin(ms->base.win);
    c = vector_size(packet_ref) - 1;

    /* re-render the whole screen when capturing */
    if (!interactive && (ms->outy >= my || c >= my) && ctx.capturing) {
        print_packets(ms);
        ms->outy = my;
    } else if (ctx.capturing && c < my) {
        werase(ms->base.win);
        for (int i = c; i >= 0; i--) {
            struct packet *p;
            char buffer[MAXLINE];

            p = vector_get_data(packet_ref, i);
            write_to_buf(buffer, MAXLINE, p);
            printnlw(ms->base.win, buffer, strlen(buffer), i, 0, ms->scrollx);
        }
        ms->outy = c + 1;
    }
    if (interactive) {
        show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
    }
    wnoutrefresh(ms->base.win);
    if (ms->subwindow.win) {
        struct packet *p;

        wbkgd(ms->subwindow.win, get_theme_colour(BACKGROUND));
        p = vector_get_data(packet_ref, ms->main_line.line_number + ms->top);
        print_protocol_information(ms, p, ms->main_line.line_number + ms->top);
        refresh_pad(ms, &ms->subwindow, 0, 0, false);
    }
    if (follow_stream && tcp_mode != NORMAL) {
        print_tcppage(ms);
    }
    print_header(ms);
    print_status();
    wnoutrefresh(ms->header);
    wnoutrefresh(status);
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

    write_to_buf(buf, MAXLINE, p);
    main_screen_update(ms, buf);
}

void main_screen_render(main_screen *ms, bool interactive_mode)
{
    int my = getmaxy(ms->base.win);

    if (vector_size(packet_ref) < my) {
        ms->outy = print_lines(ms, 0, vector_size(packet_ref), 0);
    } else {
        ms->outy = print_lines(ms, 0, my, 0);
    }
    ms->top = 0;
    if (interactive_mode) {
        interactive = true;
        show_selectionbar(ms, ms->base.win, ms->selectionbar, A_NORMAL);
    }
    main_screen_refresh((screen *) ms);
}

// TODO: Handle this differently
bool main_screen_handle_packet()
{
    return !follow_stream;
}

void main_screen_get_input(screen *s)
{
    int c = 0;
    int my;
    main_screen *ms;

    ms = (main_screen *) s;
    my = getmaxy(ms->base.win);
    c = wgetch(ms->base.win);
    if (input_mode) {
        goto_line(ms, c);
        return;
    }
    switch (c) {
    case 'c':
        push_screen(screen_cache_get(CONNECTION_SCREEN));
        break;
    case 'f':
        if (!interactive || inside_subwindow(ms))
            return;
        follow_stream = !follow_stream;
        follow_tcp_stream(ms, follow_stream);
        break;
    case 'g':
        if (!interactive) return;
        input_mode = !input_mode;
        if (input_mode) {
            werase(status);
            mvwprintw(status, 0, 0, "Go to line: ");
            curs_set(1);
        } else {
            curs_set(0);
            werase(status);
            print_status();
        }
        wrefresh(status);
        break;
    case 'h':
        push_screen(screen_cache_get(HOST_SCREEN));
        break;
    case 'i':
        main_screen_set_interactive(ms, !interactive);
        break;
    case 'm':
        hexmode = (hexmode + 1) % HEXMODES;
        if (ms->subwindow.win) {
            struct packet *p;

            p = vector_get_data(packet_ref, ms->main_line.line_number + ms->top);
            if (view_mode == DECODED_VIEW) {
                add_elements(ms, p);
            }
            print_protocol_information(ms, p, ms->main_line.line_number + ms->top);
        }
        break;
    case 'n':
        numeric = !numeric;
        break;
    case 'p':
        if (follow_stream) {
            tcp_mode = (tcp_mode + 1) % NUM_MODES;
            change_tcp_mode(ms);
        }
        break;
    case 'P':
        if (follow_stream) {
            if (tcp_mode == NORMAL)
                tcp_mode = RAW;
            else
                tcp_mode = (tcp_mode - 1) % NUM_MODES;
            change_tcp_mode(ms);
        }
        break;
    case KEY_UP:
        handle_keyup(ms, my);
        break;
    case KEY_DOWN:
        handle_keydown(ms, my);
        break;
    case KEY_LEFT:
        if (!follow_stream || tcp_mode == NORMAL)
            scroll_column(ms, -NUM_COLS_SCROLL, my);
        break;
    case KEY_RIGHT:
        if (!follow_stream || tcp_mode == NORMAL)
            scroll_column(ms, NUM_COLS_SCROLL, my);
        break;
    case KEY_ENTER:
    case '\n':
        if (input_mode) {
            goto_line(ms, c);
        } else if (interactive) {
            print_selected_packet(ms);
        }
        break;
    case KEY_ESC:
        if (input_mode) {
            goto_line(ms, c);
        } else if (ms->subwindow.win) {
            delete_subwindow(ms);
            ms->main_line.selected = false;
        } else if (interactive) {
            main_screen_set_interactive(ms, false);
        }
        break;
    case ' ':
    case KEY_NPAGE:
        scroll_page(ms, my);
        break;
    case 'b':
    case KEY_PPAGE:
        scroll_page(ms, -my);
        break;
    case KEY_HOME:
        if (interactive) {
            goto_home(ms);
        }
        break;
    case KEY_END:
        if (interactive) {
            goto_end(ms);
        }
        break;
    case KEY_F(1):
        push_screen(screen_cache_get(HELP_SCREEN));
        break;
    case KEY_F(2):
        push_screen((screen *) menu);
        break;
    case KEY_F(3):
    {
        uid_t euid = geteuid();

        if (!ctx.capturing && euid == 0) {
            main_screen_clear(ms);
            ctx.capturing = true;
            print_header(ms);
            print_status();
            wnoutrefresh(ms->base.win);
            wnoutrefresh(ms->header);
            wnoutrefresh(status);
            doupdate();
            start_scan();
        }
        break;
    }
    case KEY_F(4):
        if (ctx.capturing) {
            if (!interactive) {
                main_screen_set_interactive(ms, true);
            }
            stop_scan();
            ctx.capturing = false;
            print_status();
            wrefresh(status);
        }
        break;
    case KEY_F(5):
        if (!ctx.capturing && vector_size(packet_ref) > 0) {
            create_save_dialogue();
        }
        break;
    case KEY_F(6):
        if (!ctx.capturing && !follow_stream) {
            create_load_dialogue();
        }
        break;
    case KEY_F(7):
        view_mode = (view_mode + 1) % NUM_VIEWS;
        if (ms->subwindow.win) {
            struct packet *p;

            p = vector_get_data(packet_ref, ms->main_line.line_number + ms->top);
            if (view_mode == DECODED_VIEW) {
                add_elements(ms, p);
            }
            print_protocol_information(ms, p, ms->main_line.line_number + ms->top);
        }
        print_status();
        wrefresh(status);
        break;
    case KEY_F(10):
    case 'q':
        finish(0);
        break;
    case 's':
        push_screen(screen_cache_get(STAT_SCREEN));
        break;
    default:
        break;
    }
}

void create_load_dialogue()
{
    if (!fd) {
        if (load_filepath[0] == 0) {
            getcwd(load_filepath, MAXPATH);
        }
        fd = file_dialogue_create(" Load capture file ", FS_LOAD, load_filepath,
                                  load_handle_ok, load_handle_cancel);
        push_screen((screen *) fd);
    }
}

void create_save_dialogue()
{
    if (!sd) {
        char *info = " Save as pcap ";

        if (load_filepath[0] == 0) {
            getcwd(load_filepath, MAXPATH);
        }
        if (follow_stream) {
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
        }
        sd = file_dialogue_create(info, FS_SAVE, load_filepath, save_handle_ok,
                                  save_handle_cancel);
        push_screen((screen *) sd);
    }
}

void create_file_error_dialogue(enum file_error err, void (*callback)())
{
    char *error = get_file_error(err);

    ld = label_dialogue_create(" File Error ", error, handle_file_error, callback);
    push_screen((screen *) ld);
}

void load_handle_ok(void *file)
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

        strcpy(filename, file);
        get_file_part(filename);
        snprintf(title, MAXLINE, " Loading %s ", filename);
        clear_statistics();
        vector_clear(packet_ref, NULL);
        free_packets(NULL);
        lstat((const char *) file, buf);
        pd = progress_dialogue_create(title, buf->st_size);
        push_screen((screen *) pd);
        err = read_file(fp, read_show_progress);
        if (err == NO_ERROR) {
            int i;
            main_screen *ms;

            ms = (main_screen *) screen_cache_get(MAIN_SCREEN);
            main_screen_clear(ms);
            strcpy(ctx.filename, (const char *) file);
            i = str_find_last(ctx.filename, '/');
            if (i > 0 && i < MAXPATH) {
                strncpy(load_filepath, ctx.filename, i);
                load_filepath[i] = '\0';
            }
            pop_screen();
            SCREEN_FREE((screen *) pd);
            print_file(ms);
        } else {
            pop_screen();
            SCREEN_FREE((screen *) pd);
            memset(ctx.filename, 0, MAXPATH);
            decode_error = true;
            create_file_error_dialogue(err, create_load_dialogue);
        }
        fclose(fp);
    }
    SCREEN_FREE((screen *) fd);
    fd = NULL;
}

void load_handle_cancel(void *d __attribute__((unused)))
{
    SCREEN_FREE((screen *) fd);
    fd = NULL;
    if (decode_error) {
        main_screen *ms;

        ms = (main_screen *) screen_cache_get(MAIN_SCREEN);
        main_screen_clear(ms);
        print_header(ms);
        print_status();
        wnoutrefresh(ms->header);
        wnoutrefresh(status);
        wnoutrefresh(ms->base.win);
        doupdate();
        decode_error = false;
    }
}

void save_handle_ok(void *file)
{
    enum file_error err;
    FILE *fp;

    if ((fp = open_file((const char *) file, "w", &err)) == NULL) {
        create_file_error_dialogue(err, create_save_dialogue);
    } else {
        char title[MAXLINE];

        get_file_part(file);
        snprintf(title, MAXLINE, " Saving %s ", (char *) file);
        if (follow_stream) {
            pd = progress_dialogue_create(title, vector_size(packet_ref));
            push_screen((screen *) pd);
            switch (tcp_mode) {
            case NORMAL:
                write_pcap(fp, packet_ref, write_show_progress);
                break;
            case ASCII:
                write_ascii(fp, packet_ref, write_show_progress);
                break;
            case RAW:
                write_raw(fp, packet_ref, write_show_progress);
                break;
            default:
                break;
            }
        } else {
            pd = progress_dialogue_create(title, pstat[0].num_bytes);
            push_screen((screen *) pd);
            write_pcap(fp, packet_ref, write_show_progress);
        }
        pop_screen();
        SCREEN_FREE((screen *) pd);
        fclose(fp);
    }
    SCREEN_FREE((screen *) sd);
    sd = NULL;
}

void save_handle_cancel(void *d __attribute__((unused)))
{
    SCREEN_FREE((screen *) sd);
    sd = NULL;
}

void handle_file_error(void *callback)
{
    SCREEN_FREE((screen *) ld);
    ld = NULL;
    (* (void (*)()) callback)();
}

void write_show_progress(int size)
{
    PROGRESS_DIALOGUE_UPDATE(pd, size);
}

bool read_show_progress(unsigned char *buffer, uint32_t n, struct timeval *t)
{
    struct packet *p;

    if (!decode_packet(buffer, n, &p)) {
        return false;
    }
    p->time.tv_sec = t->tv_sec;
    p->time.tv_usec = t->tv_usec;
    vector_push_back(packet_ref, p);
    PROGRESS_DIALOGUE_UPDATE(pd, n);
    return true;
}

void show_selectionbar(main_screen *ms __attribute__((unused)), WINDOW *win, int line, uint32_t attr)
{
    mvwinchstr(win, line, 0, original_line);
    mvwchgat(win, line, 0, -1, attr, PAIR_NUMBER(get_theme_colour(SELECTIONBAR)), NULL);
}

void remove_selectionbar(main_screen *ms, WINDOW *win, int line, uint32_t attr)
{
    if (inside_subwindow(ms) && !ms->lvw) { // TODO: fix this
        int i = 0;
        bool print_line = false;

        while (original_line[i] != 0) {
            if (original_line[i++] != ' ') {
                print_line = true;
                break;
            }
        }
        if (print_line) {
            i = 0;
            while (original_line[i] != 0) {
                waddch(win, original_line[i++]);
            }
        } else {
            mvwchgat(win, line, 0, -1, attr, PAIR_NUMBER(get_theme_colour(BACKGROUND)), NULL);

        }
    } else {
        mvwchgat(win, line, 0, -1, attr, PAIR_NUMBER(get_theme_colour(BACKGROUND)), NULL);
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
        ms->top++;
    }
}

void print_header(main_screen *ms)
{
    werase(ms->header);
    if (follow_stream) {
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

        for (int i = 0; i < vector_size(packet_ref); i++) {
            struct packet *p = vector_get_data(packet_ref, i);
            uint16_t len = TCP_PAYLOAD_LEN(p);

            if (i == 0) {
                cli_addr = ipv4_src(p);
                cli_port = tcp_src(p, v4);
                srv_addr = ipv4_dst(p);
                srv_port = tcp_dst(p, v4);
            }
            if (cli_addr == ipv4_src(p) && cli_port == tcp_src(p, v4)) {
                cli_packets++;
                cli_bytes += len;
            } else {
                srv_packets++;
                srv_bytes += len;
            }
        }
        inet_ntop(AF_INET, &cli_addr, addr, sizeof(addr));
        printat(ms->header, 0, 0, txtcol, "Client address");
        if (tcp_mode == NORMAL) {
            wprintw(ms->header, ": %s:%d", addr, cli_port);
        } else {
            printat(ms->header, -1, -1, get_theme_colour(SRC_TXT), ": %s:%d",
                    addr, cli_port);
        }
        printat(ms->header, 0, 38, txtcol, "Packets");
        wprintw(ms->header, ": %d", cli_packets);
        printat(ms->header, 0, 55, txtcol, "Bytes");
        format_bytes(cli_bytes, buf, 64);
        wprintw(ms->header, ": %s", buf);
        inet_ntop(AF_INET, &srv_addr, addr, sizeof(addr));
        printat(ms->header, 1, 0, txtcol, "Server address");
        if (tcp_mode == NORMAL) {
            wprintw(ms->header, ": %s:%d", addr, srv_port);
        } else {
            printat(ms->header, -1, -1, get_theme_colour(DST_TXT), ": %s:%d",
                    addr, srv_port);
        }
        printat(ms->header, 1, 38, txtcol, "Packets");
        wprintw(ms->header, ": %d", srv_packets);
        printat(ms->header, 1, 55, txtcol, "Bytes");
        format_bytes(srv_bytes, buf, 64);
        wprintw(ms->header, ": %s", buf);
        switch (tcp_mode) {
        case NORMAL:
            printat(ms->header, 2, 0, txtcol, "Mode");
            wprintw(ms->header, ": Normal");
            break;
        case ASCII:
            printat(ms->header, 2, 0, txtcol, "Mode");
            wprintw(ms->header, ": Ascii");
            break;
        case RAW:
            printat(ms->header, 2, 0, txtcol, "Mode");
            wprintw(ms->header, ": Raw");
            break;
        default:
            break;
        }
        for (unsigned int i = 0; i < ARRAY_SIZE(header); i++) {
            mvwprintw(ms->header, 4, x, header[i].txt);
            x += header[i].width;
        }
        mvwchgat(ms->header, HEADER_HEIGHT - 1, 0, -1, A_NORMAL,
                 PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
    } else {
        int y = 0;
        int x = 0;
        char addr[INET_ADDRSTRLEN];
        int txtcol = get_theme_colour(HEADER_TXT);
        char mac[HW_ADDRSTRLEN];
        if (ctx.filename[0]) {
            printat(ms->header, y, 0, txtcol, "Filename");
            wprintw(ms->header, ": %s", ctx.filename);
        } else {
            printat(ms->header, y, 0, txtcol, "Device");
            wprintw(ms->header, ": %s", ctx.device);
        }
        inet_ntop(AF_INET, &ctx.local_addr->sin_addr, addr, sizeof(addr));
        printat(ms->header, ++y, 0, txtcol, "IPv4 address");
        wprintw(ms->header, ": %s", addr);
        HW_ADDR_NTOP(mac, ctx.mac);
        printat(ms->header, ++y, 0, txtcol, "MAC");
        wprintw(ms->header, ": %s", mac);
        y += 2;
        for (unsigned int i = 0; i < ARRAY_SIZE(header); i++) {
            mvwprintw(ms->header, y, x, header[i].txt);
            x += header[i].width;
        }
        mvwchgat(ms->header, HEADER_HEIGHT - 1, 0, -1, A_NORMAL,
                 PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
    }
}

void print_status()
{
    uid_t euid = geteuid();
    int colour = get_theme_colour(STATUS_BUTTON);
    int disabled = get_theme_colour(DISABLE);

    werase(status);
    wbkgd(status, get_theme_colour(BACKGROUND));
    mvwprintw(status, 0, 0, "F1");
    printat(status, -1, -1, colour, "%-11s", "Help");
    wprintw(status, "F2");
    printat(status, -1, -1, colour, "%-11s", "Menu");
    if (ctx.capturing || euid != 0) {
        printat(status, -1, -1, disabled, "F3");
    } else {
        wprintw(status, "F3");
    }
    printat(status, -1, -1, colour, "%-11s", "Start");
    if (ctx.capturing) {
        wprintw(status, "F4");
    } else {
        printat(status, -1, -1, disabled, "F4");
    }
    printat(status, -1, -1, colour, "%-11s", "Stop");
    if (ctx.capturing || vector_size(packet_ref) == 0) {
        printat(status, -1, -1, disabled, "F5");
        printat(status, -1, -1, colour, "%-11s", "Save");
    } else {
        wprintw(status, "F5");
        printat(status, -1, -1, colour, "%-11s", "Save");
    }
    if (ctx.capturing || follow_stream) {
        printat(status, -1, -1, disabled, "F6");
        printat(status, -1, -1, colour, "%-11s", "Load");
    } else {
        wprintw(status, "F6");
        printat(status, -1, -1, colour, "%-11s", "Load");
    }
    wprintw(status, "F7");
    if (view_mode == DECODED_VIEW) {
        printat(status, -1, -1, colour, "%-11s", "View (dec)");
    } else {
        printat(status, -1, -1, colour, "%-11s", "View (hex)");
    }
    wprintw(status, "F10");
    printat(status, -1, -1, colour, "%-11s", "Quit");
}

void goto_line(main_screen *ms, int c)
{
    static int num = 0;

    if (isdigit(c) && num < INT_MAX / 10) {
        waddch(status, c);
        num = num * 10 + c - '0';
    } else if (c == KEY_BACKSPACE) {
        int x, y;

        getyx(status, y, x);
        if (x >= 13) {
            mvwdelch(status, y, x - 1);
            num /= 10;
        }
    } else if (num && (c == '\n' || c == KEY_ENTER)) {
        if ((ms->subwindow.win && num > ms->subwindow.num_lines + vector_size(packet_ref)) ||
            (!ms->subwindow.win && num > vector_size(packet_ref))) {
            return;
        }

        int my;

        my = getmaxy(ms->base.win);
        if (num >= ms->top && num < ms->top + my) {
            remove_selectionbar(ms, ms->base.win, ms->selectionbar, A_NORMAL);
            if (ms->subwindow.win && num > ms->top + ms->subwindow.top) {
                ms->selectionbar = num - 1 + ms->subwindow.num_lines;
            } else {
                ms->selectionbar = num - 1;
            }
            show_selectionbar(ms, ms->base.win, ms->selectionbar, A_NORMAL);
        } else {
            werase(ms->base.win);
            remove_selectionbar(ms, ms->base.win, ms->selectionbar, A_NORMAL);
            if (num + my - 1 > vector_size(packet_ref)) {
                print_lines(ms, vector_size(packet_ref) - my, vector_size(packet_ref), 0);
                ms->top = vector_size(packet_ref) - my;
                ms->selectionbar = num - 1;
                show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            } else {
                print_lines(ms, num - 1, num + my - 1, 0);
                ms->selectionbar = ms->top = num - 1;
                show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
            }
        }
        wrefresh(ms->base.win);
        curs_set(0);
        werase(status);
        input_mode = false;
        num = 0;
        print_status();
    } else if (c == KEY_ESC) {
        curs_set(0);
        werase(status);
        print_status();
        num = 0;
        input_mode = false;
    }
    wrefresh(status);
}

void goto_home(main_screen *ms)
{
    if (follow_stream && tcp_mode != NORMAL) {
        tcp_page.top = 0;
        print_tcppage(ms);
    } else {
        int my = getmaxy(ms->base.win);

        werase(ms->base.win);
        print_lines(ms, 0, my, 0);
        ms->selectionbar = 0;
        ms->top = 0;
        show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
        wrefresh(ms->base.win);
    }
}

void goto_end(main_screen *ms)
{
    int my = getmaxy(ms->base.win);

    if (follow_stream && tcp_mode != NORMAL) {
        if (vector_size(tcp_page.buf) > my) {
            tcp_page.top = vector_size(tcp_page.buf) - 1 - my;
            print_tcppage(ms);
        }
    } else if (ms->outy >= my) {
        print_packets(ms);
        remove_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
        ms->selectionbar = vector_size(packet_ref) - 1;
        show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
        wrefresh(ms->base.win);
    }
}

void print_packets(main_screen *ms)
{
    int c = vector_size(packet_ref) - 1;
    int my = getmaxy(ms->base.win);

    werase(ms->base.win);

    /* print the new lines stored in vector from bottom to top of screen */
    for (int i = my - 1; i >= 0; i--, c--) {
        struct packet *p;
        char buffer[MAXLINE];

        p = vector_get_data(packet_ref, c);
        write_to_buf(buffer, MAXLINE, p);
        printnlw(ms->base.win, buffer, strlen(buffer), i, 0, ms->scrollx);
    }
    ms->top = c + 1;
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
    if (ms->selectionbar + ms->scrolly < vector_size(packet_ref) + num_lines - 1) {
        return true;
    }
    return false;
}

void scroll_column(main_screen *ms, int scrollx, int num_lines)
{
    if ((scrollx < 0 && ms->scrollx) || scrollx > 0) {
        werase(ms->base.win);
        ms->scrollx += scrollx;
        if (ms->subwindow.win) {
            ms->outy = print_lines(ms, ms->top + ms->scrolly, ms->top + num_lines, 0) + ms->scrolly;
            if (!inside_subwindow(ms)) {
                show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            }
            wnoutrefresh(ms->base.win);
            refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, false);
            doupdate();
        } else {
            ms->outy = print_lines(ms, ms->top, ms->top + num_lines, 0);
            show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            wrefresh(ms->base.win);
        }
    }
}

void handle_keyup(main_screen *ms, int num_lines __attribute__((unused)))
{
    if (follow_stream && tcp_mode != NORMAL) {
        wscrl(ms->base.win, -1);
        if (tcp_page.top > 0)
            tcp_page.top--;
        print_tcppage(ms);
        wrefresh(ms->base.win);
        return;
    }

    if (!interactive) {
        main_screen_set_interactive(ms, true);
    }

    /* scroll screen if the selection bar is at the top */
    if (ms->top > 0 && ms->selectionbar == ms->top) {
        struct packet *p;

        ms->selectionbar--;
        if (ms->subwindow.win && (ms->selectionbar >= ms->subwindow.top + ms->top + ms->subwindow.num_lines)) {
            p = vector_get_data(packet_ref, ms->selectionbar - ms->subwindow.num_lines + ms->scrolly);
        } else {
            p = vector_get_data(packet_ref, ms->selectionbar + ms->scrolly);
        }
        ms->top--;
        wscrl(ms->base.win, -1);

        int subline = ms->selectionbar - ms->top - ms->subwindow.top;
        if (p && !(ms->subwindow.win && subline > 0 && subline < ms->subwindow.num_lines)) {
            char line[MAXLINE];

            write_to_buf(line, MAXLINE, p);
            printnlw(ms->base.win, line, strlen(line), 0, 0, ms->scrollx);
            remove_selectionbar(ms, ms->base.win, 1, A_NORMAL);
            show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
            wrefresh(ms->base.win);
        }
        if (ms->subwindow.win) {
            if (inside_subwindow(ms)) {
                wnoutrefresh(ms->base.win);
            }
            handle_selectionbar(ms, KEY_UP);
            refresh_pad(ms, &ms->subwindow, 1, ms->scrollx, false);
            doupdate();
        }
    } else if (ms->selectionbar > 0) {
        int screen_line = ms->selectionbar - ms->top;

        if (ms->subwindow.win && screen_line >= ms->subwindow.top &&
            screen_line <= ms->subwindow.top + ms->subwindow.num_lines) {
            handle_selectionbar(ms, KEY_UP);
            refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, true);
        } else {
            remove_selectionbar(ms, ms->base.win, screen_line, A_NORMAL);
            show_selectionbar(ms, ms->base.win, screen_line - 1, A_NORMAL);
        }
        ms->selectionbar--;
        wrefresh(ms->base.win);
    }
}

void handle_keydown(main_screen *ms, int num_lines)
{
    if (follow_stream && tcp_mode != NORMAL) {
        wscrl(ms->base.win, 1);
        tcp_page.top++;
        print_tcppage(ms);
        wrefresh(ms->base.win);
        return;
    }

    if (!check_line(ms)) return;

    if (!interactive) {
        main_screen_set_interactive(ms, true);
    }

    /* scroll screen if the selection bar is at the bottom */
    if (ms->selectionbar - ms->top == num_lines - 1) {
        struct packet *p;

        ms->selectionbar++;
        if (ms->subwindow.win && (ms->selectionbar >= ms->subwindow.top + ms->top + ms->subwindow.num_lines)) {
            p = vector_get_data(packet_ref, ms->selectionbar - ms->subwindow.num_lines + ms->scrolly);
        } else {
            p = vector_get_data(packet_ref, ms->selectionbar + ms->scrolly);
        }
        ms->top++;
        wscrl(ms->base.win, 1);

        int subline = ms->selectionbar - ms->top - ms->subwindow.top + 1;
        if (p && !(ms->subwindow.win && subline > 0 && subline < ms->subwindow.num_lines)) {
            char line[MAXLINE];

            write_to_buf(line, MAXLINE, p);
            printnlw(ms->base.win, line, strlen(line), num_lines - 1, 0, ms->scrollx);
            remove_selectionbar(ms, ms->base.win, num_lines - 2, A_NORMAL);
            show_selectionbar(ms, ms->base.win, num_lines - 1, A_NORMAL);
            wrefresh(ms->base.win);
        }
        if (ms->subwindow.win) {
            if (inside_subwindow(ms)) {
                wnoutrefresh(ms->base.win);
            }
            handle_selectionbar(ms, KEY_DOWN);
            refresh_pad(ms, &ms->subwindow, -1, ms->scrollx, false);
            doupdate();
        }
    } else {
        int screen_line = ms->selectionbar - ms->top;

        if (ms->subwindow.win && screen_line + 1 >= ms->subwindow.top &&
            screen_line + 1 <= ms->subwindow.top + ms->subwindow.num_lines) {
            handle_selectionbar(ms, KEY_DOWN);
            refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, true);
        } else {
            remove_selectionbar(ms, ms->base.win, screen_line, A_NORMAL);
            show_selectionbar(ms, ms->base.win, screen_line + 1, A_NORMAL);
        }
        ms->selectionbar++;
        wrefresh(ms->base.win);
    }
}

void scroll_page(main_screen *ms, int num_lines)
{
    if (!interactive) {
        main_screen_set_interactive(ms, true);
    }
    if (follow_stream && tcp_mode != NORMAL) {
        tcp_page.top += num_lines;
        if (tcp_page.top < 0)
            tcp_page.top = 0;
        print_tcppage(ms);
        wrefresh(ms->base.win);
        return;
    }

    if (num_lines > 0) { /* scroll page down */
        if (vector_size(packet_ref) <= num_lines) {
            remove_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            if (ms->subwindow.win) {
                ms->selectionbar = ms->subwindow.num_lines + vector_size(packet_ref) - 1;
            } else {
                ms->selectionbar = vector_size(packet_ref) - 1;
            }
            show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            wnoutrefresh(ms->base.win);
            if (ms->subwindow.win) {
                refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, false);
            }
            doupdate();
        } else {
            int bottom = ms->top + num_lines - 1;

            remove_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            ms->selectionbar += num_lines;
            if (bottom + num_lines > vector_size(packet_ref) - 1) {
                int scroll = vector_size(packet_ref) - bottom - 1;

                wscrl(ms->base.win, scroll);
                ms->top += scroll;
                if (ms->selectionbar >= vector_size(packet_ref)) {
                    ms->selectionbar = vector_size(packet_ref) - 1;
                }
                print_lines(ms, bottom + 1, vector_size(packet_ref), vector_size(packet_ref) - scroll - ms->top);
                show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
                wnoutrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, -scroll, ms->scrollx, false);
                }
                doupdate();
            } else {
                ms->top += num_lines;
                wscrl(ms->base.win, num_lines);
                print_lines(ms, ms->top, ms->top + num_lines, 0);
                show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
                wnoutrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, -num_lines, ms->scrollx, false);
                }
                doupdate();
            }
        }
    } else { /* scroll page up */
        if (vector_size(packet_ref) <= abs(num_lines) || ms->top == 0) {
            remove_selectionbar(ms, ms->base.win, ms->selectionbar, A_NORMAL);
            ms->selectionbar = 0;
            show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
            wnoutrefresh(ms->base.win);
            if (ms->subwindow.win) {
                refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, false);
            }
            doupdate();
        } else {
            remove_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            ms->selectionbar += num_lines;
            if (ms->top + num_lines < 0) {
                wscrl(ms->base.win, -ms->top);
                if (ms->selectionbar < 0) {
                    ms->selectionbar = 0;
                }
                print_lines(ms, 0, -num_lines, 0);
                show_selectionbar(ms, ms->base.win, ms->selectionbar, A_NORMAL);
                wnoutrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, &ms->subwindow, ms->top, ms->scrollx, false);
                }
                doupdate();
                ms->top = 0;
            } else {
                wscrl(ms->base.win, num_lines);
                ms->top += num_lines;
                print_lines(ms, ms->top, ms->top - num_lines, 0);
                show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
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
    if (!vector_size(packet_ref)) return;

    if (interactive_mode) {
        interactive = true;
        ms->selectionbar = ms->top;
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
            remove_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
        }
        interactive = false;
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
            p = vector_get_data(packet_ref, from);
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
            screen_line = ms->selectionbar - ms->top;
            subline = screen_line - ms->subwindow.top;
            data = LV_GET_DATA(ms->lvw, subline);
            LV_SET_EXPANDED(ms->lvw, subline, !LV_GET_EXPANDED(ms->lvw, subline));
            if (data >= 0 && data < NUM_LAYERS) {
                selected[data] = LV_GET_EXPANDED(ms->lvw, subline);
            }
            p = vector_get_data(packet_ref, prev_selection);
            print_protocol_information(ms, p, prev_selection);
            return;
        }
    }
    screen_line = ms->selectionbar + ms->scrolly - ms->top;
    if (screen_line == ms->main_line.line_number) {
        ms->main_line.selected = !ms->main_line.selected;
    } else {
        ms->main_line.selected = true;

        /* the index to the selected line needs to be adjusted in case of an
           open subwindow */
        if (ms->subwindow.win && subwindow_on_screen(ms) &&
            screen_line > ms->subwindow.top + ms->scrolly) {
            ms->main_line.line_number = screen_line - ms->subwindow.num_lines;
            ms->selectionbar -= ms->subwindow.num_lines;
        } else {
            ms->main_line.line_number = screen_line;
        }
    }
    if (ms->main_line.selected) {
        p = vector_get_data(packet_ref, ms->selectionbar + ms->scrolly);
        if (view_mode == DECODED_VIEW) {
            add_elements(ms, p);
        }
        print_protocol_information(ms, p, ms->selectionbar + ms->scrolly);
    } else {
        delete_subwindow(ms);
    }
    prev_selection = ms->selectionbar + ms->scrolly;
}

void add_elements(main_screen *ms, struct packet *p)
{
    list_view_header *header;

    if (ms->lvw) {
        free_list_view(ms->lvw);
    }
    ms->lvw = create_list_view();

    /* inspect packet and add packet headers as elements to the list view */
    if (p->eth.ethertype <= ETH_802_3_MAX) {
        header = LV_ADD_HEADER(ms->lvw, "Ethernet 802.3", selected[ETHERNET_LAYER], ETHERNET_LAYER);
    } else {
        header = LV_ADD_HEADER(ms->lvw, "Ethernet II", selected[ETHERNET_LAYER], ETHERNET_LAYER);
    }
    add_ethernet_information(ms->lvw, header, p);
    if (p->perr == ARP_ERR || p->perr == IPv4_ERR || p->perr == IPv6_ERR) {
        header = LV_ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
        add_hexdump(ms->lvw, header, hexmode, p->eth.data + ETH_HLEN, p->eth.payload_len);
    } else {
        if (p->eth.ethertype == ETH_P_ARP) {
            header = LV_ADD_HEADER(ms->lvw, "Address Resolution Protocol (ARP)", selected[ARP], ARP);
            add_arp_information(ms->lvw, header, p);
        } else if (p->eth.ethertype == ETH_P_IP) {
            header = LV_ADD_HEADER(ms->lvw, "Internet Protocol (IPv4)", selected[IP], IP);
            add_ipv4_information(ms->lvw, header, p->eth.ipv4);
            add_transport_elements(ms, p);
        } else if (p->eth.ethertype == ETH_P_IPV6) {
            header = LV_ADD_HEADER(ms->lvw, "Internet Protocol (IPv6)", selected[IP], IP);
            add_ipv6_information(ms->lvw, header, p->eth.ipv6);
            add_transport_elements(ms, p);
        } else if (p->eth.ethertype <= ETH_802_3_MAX) {
            header = LV_ADD_HEADER(ms->lvw, "Logical Link Control (LLC)", selected[LLC], LLC);
            add_llc_information(ms->lvw, header, p);
            if (p->perr == STP_ERR) {
                header = LV_ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
                add_hexdump(ms->lvw, header, hexmode, p->eth.data + ETH_HLEN + LLC_HDR_LEN, LLC_PAYLOAD_LEN(p));
            } else {
                switch (get_eth802_type(p->eth.llc)) {
                case ETH_802_STP:
                    header = LV_ADD_HEADER(ms->lvw, "Spanning Tree Protocol (STP)", selected[STP], STP);
                    add_stp_information(ms->lvw, header, p);
                    break;
                case ETH_802_SNAP:
                    header = LV_ADD_HEADER(ms->lvw, "Subnetwork Access Protocol (SNAP)", selected[SNAP], SNAP);
                    add_snap_information(ms->lvw, header, p);
                    break;
                default:
                    header = LV_ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
                    add_hexdump(ms->lvw, header, hexmode, p->eth.data + ETH_HLEN + LLC_HDR_LEN,
                                LLC_PAYLOAD_LEN(p));
                    break;
                }
            }
        } else { /* unknown network layer protocol */
            header = LV_ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
            add_hexdump(ms->lvw, header, hexmode, p->eth.data + ETH_HLEN, p->eth.payload_len);
        }
    }
}

void add_transport_elements(main_screen *ms, struct packet *p)
{
    list_view_header *header;
    uint8_t protocol = (p->eth.ethertype == ETH_P_IP) ? p->eth.ipv4->protocol : p->eth.ipv6->next_header;

    if (p->perr == TCP_ERR || p->perr == UDP_ERR || p->perr == ICMP_ERR ||
        p->perr == IGMP_ERR || p->perr == PIM_ERR) {
        header = LV_ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
        add_hexdump(ms->lvw, header, hexmode, get_ip_payload(p), IP_PAYLOAD_LEN(p));
    } else {
        switch (protocol) {
        case IPPROTO_TCP:
        {
            uint16_t len = TCP_PAYLOAD_LEN(p);

            header = LV_ADD_HEADER(ms->lvw, "Transmission Control Protocol (TCP)",
                                   selected[TRANSPORT], TRANSPORT);
            if (p->eth.ethertype == ETH_P_IP) {
                add_tcp_information(ms->lvw, header, get_tcp(p, v4));
                if (len < p->eth.payload_len) {
                    add_app_elements(ms, p, &tcp_data(p, v4), len);
                }
            } else {
                add_tcp_information(ms->lvw, header, get_tcp(p, v6));
                if (len < p->eth.payload_len) {
                    add_app_elements(ms, p, &tcp_data(p, v6), len);
                }
            }
            break;
        }
        case IPPROTO_UDP:
        {
            uint16_t len = UDP_PAYLOAD_LEN(p);

            header = LV_ADD_HEADER(ms->lvw, "User Datagram Protocol (UDP)", selected[TRANSPORT], TRANSPORT);
            if (p->eth.ethertype == ETH_P_IP) {
                add_udp_information(ms->lvw, header, get_udp(p, v4));
                if (len < p->eth.payload_len) {
                    add_app_elements(ms, p, &udp_data(p, v4), len);
                }
            } else {
                add_udp_information(ms->lvw, header, get_udp(p, v6));
                if (len < p->eth.payload_len) {
                    add_app_elements(ms, p, &udp_data(p, v6), len);
                }
            }
            break;
        }
        case IPPROTO_ICMP:
            if (p->eth.ethertype == ETH_P_IP) {
                header = LV_ADD_HEADER(ms->lvw, "Internet Control Message Protocol (ICMP)", selected[ICMP], ICMP);
                add_icmp_information(ms->lvw, header, get_icmp(p, v4));
            }
            break;
        case IPPROTO_IGMP:
            header = LV_ADD_HEADER(ms->lvw, "Internet Group Management Protocol (IGMP)", selected[IGMP], IGMP);
            if (p->eth.ethertype == ETH_P_IP) {
                add_igmp_information(ms->lvw, header, get_igmp(p, v4));
            } else {
                add_igmp_information(ms->lvw, header, get_igmp(p, v6));
            }
            break;
        case IPPROTO_PIM:
            header = LV_ADD_HEADER(ms->lvw, "Protocol Independent Multicast (PIM)", selected[PIM], PIM);
            if (p->eth.ethertype == ETH_P_IP) {
                add_pim_information(ms->lvw, header, get_pim(p, v4));
            } else {
                add_pim_information(ms->lvw, header, get_pim(p, v6));
            }
            break;
        default:
        {
            /* unknown transport layer payload */
            uint16_t len = IP_PAYLOAD_LEN(p);

            if (len < p->eth.payload_len) {
                header = LV_ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
                add_hexdump(ms->lvw, header, hexmode, get_ip_payload(p), len);
            }
        }
        }
    }
}

void add_app_elements(main_screen *ms, struct packet *p, struct application_info *adu, uint16_t len)
{
    list_view_header *header;

    if (p->perr != NO_ERR && len > 0) {
        header = LV_ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
        add_hexdump(ms->lvw, header, hexmode, get_adu_payload(p), len);
        return;
    }

    switch (adu->utype) {
    case DNS:
    case MDNS:
    case LLMNR:
        header = LV_ADD_HEADER(ms->lvw, "Domain Name System (DNS)", selected[APPLICATION], APPLICATION);
        add_dns_information(ms->lvw, header, adu->dns, adu->utype);
        break;
    case NBNS:
        header = LV_ADD_HEADER(ms->lvw, "NetBIOS Name Service (NBNS)", selected[APPLICATION], APPLICATION);
        add_nbns_information(ms->lvw, header, adu->nbns);
        break;
    case NBDS:
        header = LV_ADD_HEADER(ms->lvw, "NetBIOS Datagram Service (NBDS)", selected[APPLICATION], APPLICATION);
        add_nbds_information(ms->lvw, header, adu->nbds);
        break;
    case HTTP:
        header = LV_ADD_HEADER(ms->lvw, "Hypertext Transfer Protocol (HTTP)", selected[APPLICATION], APPLICATION);
        add_http_information(ms->lvw, header, adu->http);
        break;
    case SSDP:
        header = LV_ADD_HEADER(ms->lvw, "Simple Service Discovery Protocol (SSDP)", selected[APPLICATION], APPLICATION);
        add_ssdp_information(ms->lvw, header, adu->ssdp);
        break;
    case SNMP:
    case SNMPTRAP:
        header = LV_ADD_HEADER(ms->lvw, "Simple Network Management Protocol (SNMP)", selected[APPLICATION], APPLICATION);
        add_snmp_information(ms->lvw, header, adu->snmp);
        break;
    case IMAP:
        header = LV_ADD_HEADER(ms->lvw, "Internet Message Access Protocol (IMAP)", selected[APPLICATION], APPLICATION);
        add_imap_information(ms->lvw, header, adu->imap);
        break;
    case TLS:
        header = LV_ADD_HEADER(ms->lvw, "Secure Socket Layer (SSL/TLS)", selected[APPLICATION], APPLICATION);
        add_tls_information(ms->lvw, header, adu->tls);
        break;
    default:
        if (len) {
            header = LV_ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
            add_hexdump(ms->lvw, header, hexmode, get_adu_payload(p), len);
        }
        break;
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
        LV_RENDER(ms->lvw, ms->subwindow.win, ms->scrollx);
        subline = ms->selectionbar - ms->top - ms->subwindow.top;
        if (inside_subwindow(ms)) {
            show_selectionbar(ms, ms->subwindow.win, subline, LV_GET_ATTR(ms->lvw, subline));
        }
        refresh_pad(ms, &ms->subwindow, 0, ms->scrollx, true);
    } else {
        int subline;
        int num_lines = (hexmode == HEXMODE_NORMAL) ? (p->eth.payload_len + ETH_HLEN) / 16 + 3 :
            (p->eth.payload_len + ETH_HLEN) / 64 + 3;

        if (ms->lvw) {
            free_list_view(ms->lvw);
            ms->lvw = NULL;
        }
        create_subwindow(ms, num_lines, lineno);
        add_winhexdump(ms->subwindow.win, 0, 2, hexmode, p);
        subline = ms->selectionbar - ms->top - ms->subwindow.top;
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
    start_line = lineno - ms->top;
    c = lineno + 1;

    /* if there is not enough space for the information to be printed, the
       screen needs to be scrolled to make room for all the lines */
    if (my - (start_line + 1) < num_lines) {
        ms->scrolly = (num_lines >= my) ? start_line : num_lines - (my - (start_line + 1));
        wscrl(ms->base.win, ms->scrolly);
        start_line -= ms->scrolly;
        ms->selectionbar -= ms->scrolly;
    }

    /* make space for protocol specific information */
    ms->subwindow.win = newpad(num_lines, mx);
    wbkgd(ms->subwindow.win, get_theme_colour(BACKGROUND));
    scrollok(ms->subwindow.win, TRUE);
    ms->subwindow.top = start_line + 1;
    ms->subwindow.num_lines = num_lines;
    ms->subwindow.lineno = lineno;
    wmove(ms->base.win, start_line + 1, 0);
    wclrtobot(ms->base.win); /* clear everything below selection bar */
    ms->outy = start_line + 1;

    if (!ms->scrolly) {
        ms->outy += print_lines(ms, c, ms->top + my, ms->outy);
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
    screen_line = ms->selectionbar - ms->top;
    delwin(ms->subwindow.win);
    ms->subwindow.win = NULL;
    ms->subwindow.num_lines = 0;
    werase(ms->base.win);

    /*
     * Print the entire screen. This can be optimized to just print the lines
     * that are below the selected line
     */
    ms->outy = print_lines(ms, ms->top, ms->top + my, 0);

    if (ms->scrolly) {
        screen_line += ms->scrolly;
        ms->selectionbar += ms->scrolly;
        ms->scrolly = 0;
    }
    show_selectionbar(ms, ms->base.win, screen_line, A_NORMAL);
    wrefresh(ms->base.win);
}

/* Returns whether the selection line is inside the subwindow or not */
bool inside_subwindow(main_screen *ms)
{
    int subline = ms->selectionbar - ms->top - ms->subwindow.top;

    return ms->subwindow.win && subline >= 0 && subline < ms->subwindow.num_lines;
}

/* Returns whether the subwindow is shown on screen or not */
bool subwindow_on_screen(main_screen *ms)
{
    int my;

    my = getmaxy(ms->base.win);
    return ms->subwindow.lineno >= ms->top && ms->subwindow.lineno <= ms->top + my;
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
    ms->main_line.line_number += scrolly;
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

void handle_selectionbar(main_screen *ms, int c)
{
    int screen_line = ms->selectionbar - ms->top;
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

void follow_tcp_stream(main_screen *ms, bool follow)
{
    if (follow) {
        hashmap_t *connections = tcp_analyzer_get_sessions();
        struct packet *p = vector_get_data(packet_ref, ms->selectionbar);
        struct tcp_endpoint_v4 endp;
        const node_t *n;
        char buf[MAXLINE];
        int i = 0;
        int my = getmaxy(ms->base.win);

        if (!is_tcp(p) || ethertype(p) != ETH_P_IP) {
            follow_stream = false;
            return;
        }
        endp.src = ipv4_src(p);
        endp.dst = ipv4_dst(p);
        endp.src_port = tcp_src(p, v4);
        endp.dst_port = tcp_dst(p, v4);
        if (!(stream = hashmap_get(connections, &endp))) {
            endp.src = ipv4_dst(p);
            endp.dst = ipv4_src(p);
            endp.src_port = tcp_dst(p, v4);
            endp.dst_port = tcp_src(p, v4);
            stream = hashmap_get(connections, &endp);
        }
        pd = progress_dialogue_create(" Finding stream ", list_size(stream->packets));
        push_screen((screen *) pd);
        main_screen_clear(ms);
        packet_ref = vector_init(list_size(stream->packets));
        n = list_begin(stream->packets);
        while (n) {
            write_to_buf(buf, MAXLINE, list_data(n));
            if (i < my) {
                printnlw(ms->base.win, buf, strlen(buf), i, 0, ms->scrollx);
            }
            vector_push_back(packet_ref, list_data(n));
            n = list_next(n);
            i++;
            PROGRESS_DIALOGUE_UPDATE(pd, 1);
        }
        pop_screen();
        SCREEN_FREE((screen *) pd);
        ms->selectionbar = 0;
        ms->top = 0;
        main_screen_set_interactive(ms, true);
        main_screen_refresh((screen *) ms);
        tcp_analyzer_subscribe(add_packet);
    } else {
        int selection = ((struct packet *) vector_get_data(packet_ref, ms->selectionbar))->num;
        int my = getmaxy(ms->base.win);

        vector_free(packet_ref, NULL);
        packet_ref = packets;
        ms->selectionbar = selection - 1;
        werase(ms->base.win);
        if (vector_size(packet_ref) < my) {
            ms->outy = print_lines(ms, 0, vector_size(packet_ref), 0);
            ms->top = 0;
            if (interactive)
                show_selectionbar(ms, ms->base.win, ms->selectionbar, A_NORMAL);
        } else {
            if (vector_size(packet_ref) - ms->selectionbar < my) {
                ms->selectionbar -= my - (vector_size(packet_ref) - ms->selectionbar);
            }
            ms->outy = print_lines(ms, ms->selectionbar, ms->selectionbar + my, 0);
            ms->top = ms->selectionbar;
            if (interactive)
                show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
        }
        werase(ms->header);
        stream = NULL;
        tcp_analyzer_unsubscribe(add_packet);
        tcp_mode = NORMAL;
        vector_clear(tcp_page.buf, free_tcp_attr);
        tcp_page.top = 0;
        main_screen_refresh((screen *) ms);
    }
}

void change_tcp_mode(main_screen *ms)
{
    tcp_page.top = 0;
    vector_clear(tcp_page.buf, free_tcp_attr);
    switch (tcp_mode) {
    case NORMAL:
        werase(ms->header);
        werase(ms->base.win);
        main_screen_render(ms, interactive);
        break;
    case ASCII:
        buffer_tcppage(ms, buffer_ascii);
        print_tcppage(ms);
        break;
    case RAW:
        buffer_tcppage(ms, buffer_raw);
        print_tcppage(ms);
        break;
    default:
        break;
    }
}

void buffer_tcppage(main_screen *ms, int (*buffer_fn)
                    (unsigned char *buf, int len, struct tcp_page_attr *attr, int pidx, int mx))
{
    int mx;
    char buf[MAXLINE];
    uint32_t cli_addr = 0;
    uint16_t cli_port = 0;
    progress_dialogue *pd;

    pd = progress_dialogue_create(" Reading packets ", vector_size(packet_ref));
    push_screen((screen *) pd);
    mx = getmaxx(ms->base.win) - 1;
    for (int i = 0; i < vector_size(packet_ref); i++) {
        struct packet *p = vector_get_data(packet_ref, i);
        unsigned char *payload = get_adu_payload(p);
        uint16_t len;
        int n;
        int j = 0;
        int col;
        struct tcp_page_attr *attr;

        PROGRESS_DIALOGUE_UPDATE(pd, 1);
        if (i == 0) {
            cli_addr = ipv4_src(p);
            cli_port = tcp_src(p, v4);
        }
        if (cli_addr == ipv4_src(p) && cli_port == tcp_src(p, v4)) {
            col = get_theme_colour(SRC_TXT);
        } else {
            col = get_theme_colour(DST_TXT);
        }
        buf[0] = '\0';
        len = TCP_PAYLOAD_LEN(p);
        if (len == 0) continue;
        n = snprintcat(buf, MAXLINE, "Packet %d\n", p->num);
        attr = calloc(1, sizeof(struct tcp_page_attr));
        attr->line = malloc(n + 1);
        strncpy(attr->line, buf, n + 1);
        vector_push_back(tcp_page.buf, attr);
        n = len;
        while (n > 0) {
            int k;

            attr = malloc(sizeof(struct tcp_page_attr));
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

int buffer_ascii(unsigned char *payload, int len, struct tcp_page_attr *attr, int pidx, int mx)
{
    int n;

    if (len < mx) {
        attr->line = malloc(len + 2);
        n = len;
    } else {
        attr->line = malloc(mx + 2);
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

int buffer_raw(unsigned char *payload, int len, struct tcp_page_attr *attr, int pidx, int mx)
{
    int n = len;

    attr->line = malloc(mx + 2);
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

void print_tcppage(main_screen *ms)
{
    int my;
    struct tcp_page_attr *attr;
    int i = tcp_page.top;

    scrollok(ms->base.win, FALSE);
    print_header(ms);
    werase(ms->base.win);
    my = getmaxy(ms->base.win);
    while (i < my + tcp_page.top && i < vector_size(tcp_page.buf)) {
        attr = vector_get_data(tcp_page.buf, i);
        wattron(ms->base.win, attr->col);
        waddstr(ms->base.win, attr->line);
        wattroff(ms->base.win, attr->col);
        i++;
    }
    wnoutrefresh(ms->header);
    wnoutrefresh(ms->base.win);
    doupdate();
    scrollok(ms->base.win, TRUE);
}

void free_tcp_attr(void *arg)
{
    struct tcp_page_attr *attr = (struct tcp_page_attr *) arg;

    free(attr->line);
    free(attr);
}

void add_packet(struct tcp_connection_v4 *conn, bool new_connection)
{
    if (new_connection) return;

    if (stream == conn) {
        vector_push_back(packet_ref, list_back(conn->packets));
        if (tcp_mode == NORMAL) {
            main_screen_print_packet(ms_ref, list_back(conn->packets));
        }
    }
}
