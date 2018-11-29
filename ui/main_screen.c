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
#include "../file_pcap.h"
#include "layout_int.h"
#include "../signal.h"
#include "dialogue.h"
#include "main_screen.h"
#include "hexdump.h"
#include "menu.h"
#include "connection_screen.h"

#define HEADER_HEIGHT 4
#define NUM_COLS_SCROLL 4

/* Get the y and x screen coordinates. The argument is the main_screen coordinate */
#define GET_SCRY(y) ((y) + HEADER_HEIGHT)
#define GET_SCRX(x) (x)

enum views {
    DECODED_VIEW,
    HEXDUMP_VIEW,
};

#define NUM_VIEWS 2

extern vector_t *packets;
extern WINDOW *status;
extern main_menu *menu;
bool selected[NUM_LAYERS]; // TODO: need to handle this differently
bool numeric = true;
int hexmode = HEXMODE_NORMAL;
static bool interactive = false;
static bool input_mode = false;
static int view_mode = DECODED_VIEW;
static label_dialogue *ld = NULL;
static file_dialogue *fd = NULL;
static file_dialogue *sd = NULL;
static progress_dialogue *pd = NULL;
static char load_filepath[MAXPATH + 1] = { 0 };
static bool decode_error = false;
static chtype original_line[MAXLINE];

static void main_screen_init(screen *s);
static void main_screen_refresh(screen *s);
static void main_screen_clear(main_screen *ms);
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
static void main_screen_get_input(screen *s);

/* Handles subwindow layout */
static void create_subwindow(main_screen *ms, int num_lines, int lineno);
static void delete_subwindow(main_screen *ms);
static bool inside_subwindow(main_screen *ms);
static void add_elements(main_screen *ms, struct packet *p);
static void add_transport_elements(main_screen *ms, struct packet *p);
static void add_app_elements(main_screen *ms, struct packet *p, struct application_info *info, uint16_t len);
static void handle_selectionbar(main_screen *ms, int c);
static void refresh_pad(main_screen *ms, int scrolly, int minx);
static bool subwindow_on_screen(main_screen *ms);

static screen_operations msop = {
    .screen_init = main_screen_init,
    .screen_free = main_screen_free,
    .screen_refresh = main_screen_refresh,
    .screen_get_input = main_screen_get_input
};

main_screen *main_screen_create()
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
    int my, mx;
    main_screen *ms;
    int c;

    ms = (main_screen *) s;
    getmaxyx(ms->base.win, my, mx);
    wbkgd(ms->base.win, get_theme_colour(BACKGROUND));
    wbkgd(ms->header, get_theme_colour(BACKGROUND));
    touchwin(ms->base.win);
    c = vector_size(packets) - 1;

    /* re-render the whole screen when capturing */
    if (!interactive && (ms->outy >= my || c >= my) && ctx.capturing) {
        goto_end(ms);
        ms->outy = my;
    } else if (ctx.capturing && c < my) {
        werase(ms->base.win);
        for (int i = c; i >= 0; i--) {
            struct packet *p;
            char buffer[MAXLINE];

            p = vector_get_data(packets, i);
            write_to_buf(buffer, MAXLINE, p);
            printnlw(ms->base.win, buffer, strlen(buffer), i, 0, ms->scrollx);
        }
        ms->outy = c + 1;
    }
    if (interactive) {
        show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
    }
    wrefresh(ms->base.win);
    if (ms->subwindow.win) {
        struct packet *p;

        wbkgd(ms->subwindow.win, get_theme_colour(BACKGROUND));
        p = vector_get_data(packets, ms->main_line.line_number + ms->top);
        print_protocol_information(ms, p, ms->main_line.line_number + ms->top);
        prefresh(ms->subwindow.win, 0, 0, GET_SCRY(ms->subwindow.top), 0,
                 GET_SCRY(my) - 1, mx);
    }
    print_header(ms);
    print_status();
}

void main_screen_refresh_pad(main_screen *ms)
{
    if (ms->subwindow.win) {
        refresh_pad(ms, 0, ms->scrollx);
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
        if (load_filepath[0] == 0) {
            getcwd(load_filepath, MAXPATH);
        }
        sd = file_dialogue_create(" Save capture file ", FS_SAVE, load_filepath,
                                  save_handle_ok, save_handle_cancel);
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
        vector_clear(packets, NULL);
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
            print_header(ms);
            print_status();
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

void load_handle_cancel(void *d)
{
    SCREEN_FREE((screen *) fd);
    fd = NULL;
    if (decode_error) {
        main_screen *ms;

        ms = (main_screen *) screen_cache_get(MAIN_SCREEN);
        main_screen_clear(ms);
        print_header(ms);
        print_status();
        wrefresh(ms->base.win);
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
        pd = progress_dialogue_create(title, pstat[0].num_bytes);
        push_screen((screen *) pd);
        write_file(fp, packets, write_show_progress);
        pop_screen();
        SCREEN_FREE((screen *) pd);
        fclose(fp);
    }
    SCREEN_FREE((screen *) sd);
    sd = NULL;
}

void save_handle_cancel(void *d)
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
    vector_push_back(packets, p);
    PROGRESS_DIALOGUE_UPDATE(pd, n);
    return true;
}

void show_selectionbar(main_screen *ms, WINDOW *win, int line, uint32_t attr)
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

void main_screen_get_input(screen *s)
{
    int c = 0;
    int my;
    main_screen *ms;

    ms = (main_screen *) s;
    my = getmaxy(ms->base.win);
    c = wgetch(ms->base.win);
    switch (c) {
    case 'c':
        push_screen(screen_cache_get(CONNECTION_SCREEN));
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
    case 'm':
        hexmode = (hexmode + 1) % HEXMODES;
        if (ms->subwindow.win) {
            struct packet *p;

            p = vector_get_data(packets, ms->main_line.line_number + ms->top);
            if (view_mode == DECODED_VIEW) {
                add_elements(ms, p);
            }
            print_protocol_information(ms, p, ms->main_line.line_number + ms->top);
        }
        break;
    case 'i':
        main_screen_set_interactive(ms, !interactive);
        break;
    case 'n':
        numeric = !numeric;
        break;
    case KEY_UP:
        handle_keyup(ms, my);
        break;
    case KEY_DOWN:
        handle_keydown(ms, my);
        break;
    case KEY_LEFT:
        scroll_column(ms, -NUM_COLS_SCROLL, my);
        break;
    case KEY_RIGHT:
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
            int my = getmaxy(ms->base.win);

            werase(ms->base.win);
            print_lines(ms, 0, my, 0);
            ms->selectionbar = 0;
            ms->top = 0;
            show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
            wrefresh(ms->base.win);
        }
        break;
    case KEY_END:
        if (interactive) {
            if (ms->outy >= my) {
                goto_end(ms);
            }
            remove_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            ms->selectionbar = vector_size(packets) - 1;
            show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            wrefresh(ms->base.win);
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
            wrefresh(ms->base.win);
            print_header(ms);
            print_status();
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
        }
        break;
    case KEY_F(5):
        if (!ctx.capturing && vector_size(packets) > 0) {
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

            p = vector_get_data(packets, ms->main_line.line_number + ms->top);
            if (view_mode == DECODED_VIEW) {
                add_elements(ms, p);
            }
            print_protocol_information(ms, p, ms->main_line.line_number + ms->top);
        }
        print_status();
        break;
    case KEY_F(10):
    case 'q':
        finish();
        break;
    case 's':
        push_screen(screen_cache_get(STAT_SCREEN));
        break;
    default:
        if (input_mode) {
            goto_line(ms, c);
        }
        break;
    }
}

void print_header(main_screen *ms)
{
    int y = 0;
    char addr[INET_ADDRSTRLEN];
    int txtcol = get_theme_colour(HEADER_TXT);

    if (ctx.filename[0]) {
        printat(ms->header, y, 0, txtcol, "Filename");
        wprintw(ms->header, ": %s", ctx.filename);
    } else {
        printat(ms->header, y, 0, txtcol, "Device");
        wprintw(ms->header, ": %s", ctx.device);
    }
    inet_ntop(AF_INET, &local_addr->sin_addr, addr, sizeof(addr));
    printat(ms->header, ++y, 0, txtcol, "Local address");
    wprintw(ms->header, ": %s", addr);
    y += 2;
    mvwprintw(ms->header, y, 0, "Number");
    mvwprintw(ms->header, y, NUM_WIDTH, "Time");
    mvwprintw(ms->header, y, NUM_WIDTH + TIME_WIDTH, "Source");
    mvwprintw(ms->header, y, ADDR_WIDTH + NUM_WIDTH + TIME_WIDTH, "Destination");
    mvwprintw(ms->header, y, 2 * ADDR_WIDTH + NUM_WIDTH + TIME_WIDTH, "Protocol");
    mvwprintw(ms->header, y, 2 * ADDR_WIDTH + NUM_WIDTH + TIME_WIDTH + PROT_WIDTH, "Info");
    mvwchgat(ms->header, y, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
    wrefresh(ms->header);
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
    if (ctx.capturing || vector_size(packets) == 0) {
        printat(status, -1, -1, disabled, "F5");
        printat(status, -1, -1, colour, "%-11s", "Save");
    } else {
        wprintw(status, "F5");
        printat(status, -1, -1, colour, "%-11s", "Save");
    }
    if (ctx.capturing) {
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
    wrefresh(status);
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
        if ((ms->subwindow.win && num > ms->subwindow.num_lines + vector_size(packets)) ||
            (!ms->subwindow.win && num > vector_size(packets))) {
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
            if (num + my - 1 > vector_size(packets)) {
                print_lines(ms, vector_size(packets) - my, vector_size(packets), 0);
                ms->top = vector_size(packets) - my;
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

void goto_end(main_screen *ms)
{
    int c = vector_size(packets) - 1;
    int my = getmaxy(ms->base.win);

    werase(ms->base.win);

    /* print the new lines stored in vector from bottom to top of screen */
    for (int i = my - 1; i >= 0; i--, c--) {
        struct packet *p;
        char buffer[MAXLINE];

        p = vector_get_data(packets, c);
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
    if (ms->selectionbar + ms->scrolly < vector_size(packets) + num_lines - 1) {
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
            wrefresh(ms->base.win);
            refresh_pad(ms, 0, ms->scrollx);
        } else {
            ms->outy = print_lines(ms, ms->top, ms->top + num_lines, 0);
            show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            wrefresh(ms->base.win);
        }
    }
}

void handle_keyup(main_screen *ms, int num_lines)
{
    if (!interactive) {
        main_screen_set_interactive(ms, true);
    }

    /* scroll screen if the selection bar is at the top */
    if (ms->top > 0 && ms->selectionbar == ms->top) {
        struct packet *p;

        ms->selectionbar--;
        if (ms->subwindow.win && (ms->selectionbar >= ms->subwindow.top + ms->top + ms->subwindow.num_lines)) {
            p = vector_get_data(packets, ms->selectionbar - ms->subwindow.num_lines + ms->scrolly);
        } else {
            p = vector_get_data(packets, ms->selectionbar + ms->scrolly);
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
                wrefresh(ms->base.win);
            }
            handle_selectionbar(ms, KEY_UP);
            refresh_pad(ms, 1, ms->scrollx);
        }
    } else if (ms->selectionbar > 0) {
        int screen_line = ms->selectionbar - ms->top;

        if (ms->subwindow.win && screen_line >= ms->subwindow.top &&
            screen_line <= ms->subwindow.top + ms->subwindow.num_lines) {
            handle_selectionbar(ms, KEY_UP);
            refresh_pad(ms, 0, ms->scrollx);
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
    if (!check_line(ms)) return;

    if (!interactive) {
        main_screen_set_interactive(ms, true);
    }

    /* scroll screen if the selection bar is at the bottom */
    if (ms->selectionbar - ms->top == num_lines - 1) {
        struct packet *p;

        ms->selectionbar++;
        if (ms->subwindow.win && (ms->selectionbar >= ms->subwindow.top + ms->top + ms->subwindow.num_lines)) {
            p = vector_get_data(packets, ms->selectionbar - ms->subwindow.num_lines + ms->scrolly);
        } else {
            p = vector_get_data(packets, ms->selectionbar + ms->scrolly);
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
                wrefresh(ms->base.win);
            }
            handle_selectionbar(ms, KEY_DOWN);
            refresh_pad(ms, -1, ms->scrollx);
        }
    } else {
        int screen_line = ms->selectionbar - ms->top;

        if (ms->subwindow.win && screen_line + 1 >= ms->subwindow.top &&
            screen_line + 1 <= ms->subwindow.top + ms->subwindow.num_lines) {
            handle_selectionbar(ms, KEY_DOWN);
            refresh_pad(ms, 0, ms->scrollx);
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
    if (num_lines > 0) { /* scroll page down */
        if (vector_size(packets) <= num_lines) {
            remove_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            if (ms->subwindow.win) {
                ms->selectionbar = ms->subwindow.num_lines + vector_size(packets) - 1;
            } else {
                ms->selectionbar = vector_size(packets) - 1;
            }
            show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            wrefresh(ms->base.win);
            if (ms->subwindow.win) {
                refresh_pad(ms, 0, ms->scrollx);
            }
        } else {
            int bottom = ms->top + num_lines - 1;

            remove_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
            ms->selectionbar += num_lines;
            if (bottom + num_lines > vector_size(packets) - 1) {
                int scroll = vector_size(packets) - bottom - 1;

                wscrl(ms->base.win, scroll);
                ms->top += scroll;
                if (ms->selectionbar >= vector_size(packets)) {
                    ms->selectionbar = vector_size(packets) - 1;
                }
                print_lines(ms, bottom + 1, vector_size(packets), vector_size(packets) - scroll - ms->top);
                show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
                wrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, -scroll, ms->scrollx);
                }
            } else {
                ms->top += num_lines;
                wscrl(ms->base.win, num_lines);
                print_lines(ms, ms->top, ms->top + num_lines, 0);
                show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
                wrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, -num_lines, ms->scrollx);
                }
            }
        }
    } else { /* scroll page up */
        if (vector_size(packets) <= abs(num_lines) || ms->top == 0) {
            remove_selectionbar(ms, ms->base.win, ms->selectionbar, A_NORMAL);
            ms->selectionbar = 0;
            show_selectionbar(ms, ms->base.win, 0, A_NORMAL);
            wrefresh(ms->base.win);
            if (ms->subwindow.win) {
                refresh_pad(ms, 0, ms->scrollx);
            }
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
                wrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, ms->top, ms->scrollx);
                }
                ms->top = 0;
            } else {
                wscrl(ms->base.win, num_lines);
                ms->top += num_lines;
                print_lines(ms, ms->top, ms->top - num_lines, 0);
                show_selectionbar(ms, ms->base.win, ms->selectionbar - ms->top, A_NORMAL);
                wrefresh(ms->base.win);
                if (ms->subwindow.win) {
                    refresh_pad(ms, -num_lines, ms->scrollx);
                }
            }
        }
    }
}

void main_screen_set_interactive(main_screen *ms, bool interactive_mode)
{
    if (!vector_size(packets)) return;

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
            goto_end(ms);
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
            p = vector_get_data(packets, from);
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
            p = vector_get_data(packets, prev_selection);
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
        p = vector_get_data(packets, ms->selectionbar + ms->scrolly);
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
            add_ipv4_information(ms->lvw, header, p->eth.ip);
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
    uint8_t protocol = (p->eth.ethertype == ETH_P_IP) ? p->eth.ip->protocol : p->eth.ipv6->next_header;

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
                add_tcp_information(ms->lvw, header, &p->eth.ip->tcp);
                if (len < p->eth.payload_len) {
                    add_app_elements(ms, p, &p->eth.ip->tcp.data, len);
                }
            } else {
                add_tcp_information(ms->lvw, header, &p->eth.ipv6->tcp);
                if (len < p->eth.payload_len) {
                    add_app_elements(ms, p, &p->eth.ipv6->tcp.data, len);
                }
            }
            break;
        }
        case IPPROTO_UDP:
        {
            uint16_t len = UDP_PAYLOAD_LEN(p);

            header = LV_ADD_HEADER(ms->lvw, "User Datagram Protocol (UDP)", selected[TRANSPORT], TRANSPORT);
            if (p->eth.ethertype == ETH_P_IP) {
                add_udp_information(ms->lvw, header, &p->eth.ip->udp);
                if (len < p->eth.payload_len) {
                    add_app_elements(ms, p, &p->eth.ip->udp.data, len);
                }
            } else {
                add_udp_information(ms->lvw, header, &p->eth.ipv6->udp);
                if (len < p->eth.payload_len) {
                    add_app_elements(ms, p, &p->eth.ipv6->udp.data, len);
                }
            }
            break;
        }
        case IPPROTO_ICMP:
            if (p->eth.ethertype == ETH_P_IP) {
                header = LV_ADD_HEADER(ms->lvw, "Internet Control Message Protocol (ICMP)", selected[ICMP], ICMP);
                add_icmp_information(ms->lvw, header, &p->eth.ip->icmp);
            }
            break;
        case IPPROTO_IGMP:
            header = LV_ADD_HEADER(ms->lvw, "Internet Group Management Protocol (IGMP)", selected[IGMP], IGMP);
            if (p->eth.ethertype == ETH_P_IP) {
                add_igmp_information(ms->lvw, header, &p->eth.ip->igmp);
            } else {
                add_igmp_information(ms->lvw, header, &p->eth.ipv6->igmp);
            }
            break;
        case IPPROTO_PIM:
            header = LV_ADD_HEADER(ms->lvw, "Protocol Independent Multicast (PIM)", selected[PIM], PIM);
            if (p->eth.ethertype == ETH_P_IP) {
                add_pim_information(ms->lvw, header, &p->eth.ip->pim);
            } else {
                add_pim_information(ms->lvw, header, &p->eth.ipv6->pim);
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
        refresh_pad(ms, 0, ms->scrollx);
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
        refresh_pad(ms, 0, ms->scrollx);
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
void refresh_pad(main_screen *ms, int scrolly, int minx)
{
    int my, mx;

    getmaxyx(ms->base.win, my, mx);
    ms->subwindow.top += scrolly;
    ms->main_line.line_number += scrolly;
    if (ms->subwindow.top <= 0) {
        prefresh(ms->subwindow.win, abs(ms->subwindow.top), minx, GET_SCRY(0), 0, GET_SCRY(my) - 1, mx);
    } else {
        prefresh(ms->subwindow.win, 0, minx, GET_SCRY(ms->subwindow.top), 0, GET_SCRY(my) - 1, mx);
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
