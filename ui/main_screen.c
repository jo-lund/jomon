#include <string.h>
#include <signal.h>
#include <linux/igmp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
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
#include "stat_screen.h"
#include "../signal.h"
#include "dialogue.h"
#include "main_screen.h"
#include "hexdump.h"

#define HEADER_HEIGHT 4
#define STATUS_HEIGHT 1
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
bool selected[NUM_LAYERS]; // TODO: need to handle this differently
bool numeric = true;

static main_context *ctx;
static bool interactive = false;
static bool input_mode = false;
static int hexmode = HEXMODE_NORMAL;
static int view_mode = DECODED_VIEW;
static label_dialogue *ld = NULL;
static file_dialogue *fd = NULL;
static file_dialogue *sd = NULL;
static progress_dialogue *pd = NULL;
static char load_filepath[MAXPATH + 1] = { 0 };
static bool decode_error = false;
static main_screen *mscr;
static chtype original_line[MAXLINE];

static bool check_line(main_screen *ms);
static void handle_keydown(main_screen *ms, int num_lines);
static void handle_keyup(main_screen *ms, int num_lines);
static void scroll_page(main_screen *ms, int num_lines);
static void scroll_column(main_screen *ms, int scrollx, int num_lines);
static void scroll_window(main_screen *ms);
static int print_lines(main_screen *ms, int from, int to, int y);
static void print_header(main_screen *ms);
static void print_status(main_screen *ms);
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

void main_screen_render(main_screen *ms, char *buf)
{
    int my;

    my = getmaxy(ms->pktlist);
    if (!interactive || (interactive && ms->outy < my)) {
        scroll_window(ms);
        printnlw(ms->pktlist, buf, strlen(buf), ms->outy, 0, ms->scrollx);
        ms->outy++;
        if (screen_stack_empty()) {
            wrefresh(ms->pktlist);
        }
    }
}

main_screen *main_screen_create(int nlines, int ncols, main_context *mctx)
{
    main_screen *ms;

    ms = malloc(sizeof(main_screen));
    ms->outy = 0;
    ms->selection_line = 0;
    ms->top = 0;
    ms->scrolly = 0;
    ms->scrollx = 0;
    ms->lvw = NULL;
    ms->header = newwin(HEADER_HEIGHT, ncols, 0, 0);
    ms->pktlist = newwin(nlines - HEADER_HEIGHT - STATUS_HEIGHT, ncols, HEADER_HEIGHT, 0);
    ms->status = newwin(STATUS_HEIGHT, ncols, nlines - STATUS_HEIGHT, 0);
    memset(&ms->subwindow, 0, sizeof(ms->subwindow));
    mscr = ms;
    ctx = mctx;
    nodelay(ms->pktlist, TRUE); /* input functions must be non-blocking */
    keypad(ms->pktlist, TRUE);
    scrollok(ms->pktlist, TRUE);
    print_header(ms);
    print_status(ms);
    return ms;
}

void main_screen_free(main_screen *ms)
{
    if (ms->subwindow.win) {
        delwin(ms->subwindow.win);
    }
    delwin(ms->header);
    delwin(ms->pktlist);
    delwin(ms->status);
    free(ms);
    mscr = NULL;
}

void main_screen_clear(main_screen *ms)
{
    main_screen_set_interactive(ms, false);
    werase(ms->header);
    werase(ms->pktlist);
    ms->selection_line = 0;
    ms->top = 0;
    ms->outy = 0;
}

void main_screen_refresh(main_screen *ms)
{
    int my, mx;

    getmaxyx(ms->pktlist, my, mx);
    touchwin(ms->pktlist);
    touchwin(ms->status);
    touchwin(ms->header);
    wnoutrefresh(ms->pktlist);
    wnoutrefresh(ms->header);
    wnoutrefresh(ms->status);
    doupdate();
    if (ms->subwindow.win) {
        prefresh(ms->subwindow.win, 0, 0, GET_SCRY(ms->subwindow.top), 0,
                 GET_SCRY(my) - 1, mx);
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

    if ((fp = open_file((const char *) file, "r", &err)) == NULL) {
        create_file_error_dialogue(err, create_load_dialogue);
    } else {
        struct stat buf[sizeof(struct stat)];
        char filename[MAXPATH + 1];
        char title[MAXLINE];

        strcpy(filename, file);
        get_file_part(filename);
        snprintf(title, MAXLINE, " Loading %s ", filename);
        vector_clear(packets, free_packet);
        clear_statistics();
        lstat((const char *) file, buf);
        pd = progress_dialogue_create(title, buf->st_size);
        push_screen((screen *) pd);
        err = read_file(fp, read_show_progress);
        if (err == NO_ERROR) {
            int i;

            main_screen_clear(mscr);
            strcpy(ctx->filename, (const char *) file);
            i = str_find_last(ctx->filename, '/');
            if (i > 0 && i < MAXPATH) {
                strncpy(load_filepath, ctx->filename, i);
                load_filepath[i] = '\0';
            }
            pop_screen();
            progress_dialogue_free(pd);
            print_header(mscr);
            print_status(mscr);
            print_file(mscr);
        } else {
            pop_screen();
            progress_dialogue_free(pd);
            memset(ctx->filename, 0, MAXPATH);
            decode_error = true;
            create_file_error_dialogue(err, create_load_dialogue);
        }
        fclose(fp);
    }
    file_dialogue_free(fd);
    fd = NULL;
}

void load_handle_cancel(void *d)
{
    file_dialogue_free(fd);
    fd = NULL;
    if (decode_error) {
        main_screen_clear(mscr);
        print_header(mscr);
        print_status(mscr);
        wrefresh(mscr->pktlist);
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
        progress_dialogue_free(pd);
        fclose(fp);
    }
    file_dialogue_free(sd);
    sd = NULL;
}

void save_handle_cancel(void *d)
{
    file_dialogue_free(sd);
    sd = NULL;
}

void handle_file_error(void *callback)
{
    label_dialogue_free(ld);
    ld = NULL;
    (* ((void (*)()) callback))();
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
    mvwchgat(win, line, 0, -1, attr, 2, NULL);
}

void remove_selectionbar(main_screen *ms, WINDOW *win, int line, uint32_t attr)
{
    if (inside_subwindow(ms) && !ms->lvw) { // TODO: fix this
        int i = 0;

        while (original_line[i] != 0) {
            mvwaddch(win, line, i, original_line[i++]);
        }
    } else {
        mvwchgat(win, line, 0, -1, attr, PAIR_NUMBER(attr), NULL);
    }
}

/* scroll the window if necessary */
void scroll_window(main_screen *ms)
{
    int my;

    my = getmaxy(ms->pktlist);
    if (ms->outy >= my) {
        ms->outy = my - 1;
        scroll(ms->pktlist);
        ms->top++;
    }
}

void main_screen_get_input(main_screen *ms)
{
    int c = 0;
    int my;

    my = getmaxy(ms->pktlist);
    c = wgetch(ms->pktlist);
    switch (c) {
    case 'i':
        main_screen_set_interactive(ms, !interactive);
        break;
    case KEY_F(10):
    case 'q':
        finish();
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
            int my = getmaxy(ms->pktlist);

            werase(ms->pktlist);
            print_lines(ms, 0, my, 0);
            ms->selection_line = 0;
            ms->top = 0;
            show_selectionbar(ms, ms->pktlist, 0, A_NORMAL);
            wrefresh(ms->pktlist);
        }
        break;
    case KEY_END:
        if (interactive) {
            if (ms->outy >= my) {
                goto_end(ms);
            }
            remove_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
            ms->selection_line = vector_size(packets) - 1;
            show_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
            wrefresh(ms->pktlist);
        }
        break;
    case KEY_F(1):
    {
        screen *scr = get_screen(HELP_SCREEN);

        if (scr) {
            push_screen(scr);
        } else {
            push_screen(help_screen_create());
        }
        break;
    }
    case KEY_F(2):
        break;
    case KEY_F(3):
    {
        uid_t euid = geteuid();

        if (!ctx->capturing && euid == 0) {
            if (interactive) {
                main_screen_set_interactive(ms, false);
            }
            werase(ms->pktlist);
            wrefresh(ms->pktlist);
            ms->outy = 0;
            ctx->capturing = true;
            print_status(ms);
            start_scan();
        }
        break;
    }
    case KEY_F(4):
        if (ctx->capturing) {
            if (!interactive) {
                main_screen_set_interactive(ms, true);
            }
            stop_scan();
            ctx->capturing = false;
            print_status(ms);
        }
        break;
    case KEY_F(5):
        if (!ctx->capturing && vector_size(packets) > 0) {
            create_save_dialogue();
        }
        break;
    case KEY_F(6):
        if (!ctx->capturing) {
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
        print_status(ms);
        break;
    case 'g':
        if (!interactive) return;
        input_mode = !input_mode;
        if (input_mode) {
            werase(ms->status);
            mvwprintw(ms->status, 0, 0, "Go to line: ");
            curs_set(1);
        } else {
            curs_set(0);
            werase(ms->status);
            print_status(ms);
        }
        wrefresh(ms->status);
        break;
    case 's':
    {
        screen *scr = get_screen(STAT_SCREEN);

        if (scr) {
            push_screen(scr);
        } else {
            push_screen(stat_screen_create());
        }
        break;
    }
    case 'h':
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

    if (ctx->filename[0]) {
        printat(ms->header, y, 0, COLOR_PAIR(4) | A_BOLD, "Filename");
        wprintw(ms->header, ": %s", ctx->filename);
    } else {
        printat(ms->header, y, 0, COLOR_PAIR(4) | A_BOLD, "Device");
        wprintw(ms->header, ": %s", ctx->device);
    }
    inet_ntop(AF_INET, &local_addr->sin_addr, addr, sizeof(addr));
    printat(ms->header, ++y, 0, COLOR_PAIR(4) | A_BOLD, "Local address");
    wprintw(ms->header, ": %s", addr);
    y += 2;
    mvwprintw(ms->header, y, 0, "Number");
    mvwprintw(ms->header, y, NUM_WIDTH, "Time");
    mvwprintw(ms->header, y, NUM_WIDTH + TIME_WIDTH, "Source");
    mvwprintw(ms->header, y, ADDR_WIDTH + NUM_WIDTH + TIME_WIDTH, "Destination");
    mvwprintw(ms->header, y, 2 * ADDR_WIDTH + NUM_WIDTH + TIME_WIDTH, "Protocol");
    mvwprintw(ms->header, y, 2 * ADDR_WIDTH + NUM_WIDTH + TIME_WIDTH + PROT_WIDTH, "Info");
    mvwchgat(ms->header, y, 0, -1, A_STANDOUT, 0, NULL);
    wrefresh(ms->header);
}

void print_status(main_screen *ms)
{
    uid_t euid = geteuid();

    mvwprintw(ms->status, 0, 0, "F1");
    printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "Help");
    wprintw(ms->status, "F2");
    printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "Menu");
    if (ctx->capturing || euid != 0) {
        printat(ms->status, -1, -1, GREY, "F3");
    } else {
        wprintw(ms->status, "F3");
    }
    printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "Start");
    if (ctx->capturing) {
        wprintw(ms->status, "F4");
    } else {
        printat(ms->status, -1, -1, GREY, "F4");
    }
    printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "Stop");
    if (ctx->capturing || vector_size(packets) == 0) {
        printat(ms->status, -1, -1, GREY, "F5");
        printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "Save");
    } else {
        wprintw(ms->status, "F5");
        printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "Save");
    }
    if (ctx->capturing) {
        printat(ms->status, -1, -1, GREY, "F6");
        printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "Load");
    } else {
        wprintw(ms->status, "F6");
        printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "Load");
    }
    wprintw(ms->status, "F7");
    if (view_mode == DECODED_VIEW) {
        printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "View (dec)");
    } else {
        printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "View (hex)");
    }
    wprintw(ms->status, "F10");
    printat(ms->status, -1, -1, COLOR_PAIR(2), "%-11s", "Quit");
    wrefresh(ms->status);
}

void goto_line(main_screen *ms, int c)
{
    static int num = 0;

    if (isdigit(c) && num < INT_MAX / 10) {
        waddch(ms->status, c);
        num = num * 10 + c - '0';
    } else if (c == KEY_BACKSPACE) {
        int x, y;

        getyx(ms->status, y, x);
        if (x >= 13) {
            mvwdelch(ms->status, y, x - 1);
            num /= 10;
        }
    } else if (num && (c == '\n' || c == KEY_ENTER)) {
        if ((ms->subwindow.win && num > ms->subwindow.num_lines + vector_size(packets)) ||
            (!ms->subwindow.win && num > vector_size(packets))) {
            return;
        }

        int my;

        my = getmaxy(ms->pktlist);
        if (num >= ms->top && num < ms->top + my) {
            remove_selectionbar(ms, ms->pktlist, ms->selection_line, A_NORMAL);
            if (ms->subwindow.win && num > ms->top + ms->subwindow.top) {
                ms->selection_line = num - 1 + ms->subwindow.num_lines;
            } else {
                ms->selection_line = num - 1;
            }
            show_selectionbar(ms, ms->pktlist, ms->selection_line, A_NORMAL);
        } else {
            werase(ms->pktlist);
            remove_selectionbar(ms, ms->pktlist, ms->selection_line, A_NORMAL);
            if (num + my - 1 > vector_size(packets)) {
                print_lines(ms, vector_size(packets) - my, vector_size(packets), 0);
                ms->top = vector_size(packets) - my;
                ms->selection_line = num - 1;
                show_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
            } else {
                print_lines(ms, num - 1, num + my - 1, 0);
                ms->selection_line = ms->top = num - 1;
                show_selectionbar(ms, ms->pktlist, 0, A_NORMAL);
            }
        }
        wrefresh(ms->pktlist);
        curs_set(0);
        werase(ms->status);
        input_mode = false;
        num = 0;
        print_status(ms);
    } else if (c == KEY_ESC) {
        curs_set(0);
        werase(ms->status);
        print_status(ms);
        num = 0;
        input_mode = false;
    }
    wrefresh(ms->status);
}

void goto_end(main_screen *ms)
{
    int c = vector_size(packets) - 1;
    int my = getmaxy(ms->pktlist);

    werase(ms->pktlist);

    /* print the new lines stored in vector from bottom to top of screen */
    for (int i = my - 1; i >= 0; i--, c--) {
        struct packet *p;
        char buffer[MAXLINE];

        p = vector_get_data(packets, c);
        write_to_buf(buffer, MAXLINE, p);
        printnlw(ms->pktlist, buffer, strlen(buffer), i, 0, ms->scrollx);
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
    if (ms->selection_line + ms->scrolly < vector_size(packets) + num_lines - 1) {
        return true;
    }
    return false;
}

void scroll_column(main_screen *ms, int scrollx, int num_lines)
{
    if ((scrollx < 0 && ms->scrollx) || scrollx > 0) {
        werase(ms->pktlist);
        ms->scrollx += scrollx;
        if (ms->subwindow.win) {
            ms->outy = print_lines(ms, ms->top + ms->scrolly, ms->top + num_lines, 0);
            if (!inside_subwindow(ms)) {
                show_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
            }
            wrefresh(ms->pktlist);
            refresh_pad(ms, 0, ms->scrollx);
        } else {
            ms->outy = print_lines(ms, ms->top, ms->top + num_lines, 0);
            show_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
            wrefresh(ms->pktlist);
        }
    }
}

void handle_keyup(main_screen *ms, int num_lines)
{
    if (!interactive) {
        main_screen_set_interactive(ms, true);
    }

    /* scroll screen if the selection bar is at the top */
    if (ms->top > 0 && ms->selection_line == ms->top) {
        struct packet *p;

        ms->selection_line--;
        if (ms->subwindow.win && (ms->selection_line >= ms->subwindow.top + ms->top + ms->subwindow.num_lines)) {
            p = vector_get_data(packets, ms->selection_line - ms->subwindow.num_lines + ms->scrolly);
        } else {
            p = vector_get_data(packets, ms->selection_line + ms->scrolly);
        }
        ms->top--;
        wscrl(ms->pktlist, -1);

        int subline = ms->selection_line - ms->top - ms->subwindow.top;
        if (p && !(ms->subwindow.win && subline > 0 && subline < ms->subwindow.num_lines)) {
            char line[MAXLINE];

            write_to_buf(line, MAXLINE, p);
            printnlw(ms->pktlist, line, strlen(line), 0, 0, ms->scrollx);
            remove_selectionbar(ms, ms->pktlist, 1, A_NORMAL);
            show_selectionbar(ms, ms->pktlist, 0, A_NORMAL);
            wrefresh(ms->pktlist);
        }
        if (ms->subwindow.win) {
            if (inside_subwindow(ms)) {
                wrefresh(ms->pktlist);
            }
            handle_selectionbar(ms, KEY_UP);
            refresh_pad(ms, 1, ms->scrollx);
        }
    } else if (ms->selection_line > 0) {
        int screen_line = ms->selection_line - ms->top;

        if (ms->subwindow.win && screen_line >= ms->subwindow.top &&
            screen_line <= ms->subwindow.top + ms->subwindow.num_lines) {
            handle_selectionbar(ms, KEY_UP);
            refresh_pad(ms, 0, ms->scrollx);
        } else {
            remove_selectionbar(ms, ms->pktlist, screen_line, A_NORMAL);
            show_selectionbar(ms, ms->pktlist, screen_line - 1, A_NORMAL);
        }
        ms->selection_line--;
        wrefresh(ms->pktlist);
    }
}

void handle_keydown(main_screen *ms, int num_lines)
{
    if (!check_line(ms)) return;

    if (!interactive) {
        main_screen_set_interactive(ms, true);
    }

    /* scroll screen if the selection bar is at the bottom */
    if (ms->selection_line - ms->top == num_lines - 1) {
        struct packet *p;

        ms->selection_line++;
        if (ms->subwindow.win && (ms->selection_line >= ms->subwindow.top + ms->top + ms->subwindow.num_lines)) {
            p = vector_get_data(packets, ms->selection_line - ms->subwindow.num_lines + ms->scrolly);
        } else {
            p = vector_get_data(packets, ms->selection_line + ms->scrolly);
        }
        ms->top++;
        wscrl(ms->pktlist, 1);

        int subline = ms->selection_line - ms->top - ms->subwindow.top + 1;
        if (p && !(ms->subwindow.win && subline > 0 && subline < ms->subwindow.num_lines)) {
            char line[MAXLINE];

            write_to_buf(line, MAXLINE, p);
            printnlw(ms->pktlist, line, strlen(line), num_lines - 1, 0, ms->scrollx);
            remove_selectionbar(ms, ms->pktlist, num_lines - 2, A_NORMAL);
            show_selectionbar(ms, ms->pktlist, num_lines - 1, A_NORMAL);
            wrefresh(ms->pktlist);
        }
        if (ms->subwindow.win) {
            if (inside_subwindow(ms)) {
                wrefresh(ms->pktlist);
            }
            handle_selectionbar(ms, KEY_DOWN);
            refresh_pad(ms, -1, ms->scrollx);
        }
    } else {
        int screen_line = ms->selection_line - ms->top;

        if (ms->subwindow.win && screen_line + 1 >= ms->subwindow.top &&
            screen_line + 1 <= ms->subwindow.top + ms->subwindow.num_lines) {
            handle_selectionbar(ms, KEY_DOWN);
            refresh_pad(ms, 0, ms->scrollx);
        } else {
            remove_selectionbar(ms, ms->pktlist, screen_line, A_NORMAL);
            show_selectionbar(ms, ms->pktlist, screen_line + 1, A_NORMAL);
        }
        ms->selection_line++;
        wrefresh(ms->pktlist);
    }
}

void scroll_page(main_screen *ms, int num_lines)
{
    if (!interactive) {
        main_screen_set_interactive(ms, true);
    }
    if (num_lines > 0) { /* scroll page down */
        if (vector_size(packets) <= num_lines) {
            remove_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
            if (ms->subwindow.win) {
                ms->selection_line = ms->subwindow.num_lines + vector_size(packets) - 1;
            } else {
                ms->selection_line = vector_size(packets) - 1;
            }
            show_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
            wrefresh(ms->pktlist);
            if (ms->subwindow.win) {
                refresh_pad(ms, 0, ms->scrollx);
            }
        } else {
            int bottom = ms->top + num_lines - 1;

            remove_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
            ms->selection_line += num_lines;
            if (bottom + num_lines > vector_size(packets) - 1) {
                int scroll = vector_size(packets) - bottom - 1;

                wscrl(ms->pktlist, scroll);
                ms->top += scroll;
                if (ms->selection_line >= vector_size(packets)) {
                    ms->selection_line = vector_size(packets) - 1;
                }
                print_lines(ms, bottom + 1, vector_size(packets), vector_size(packets) - scroll - ms->top);
                show_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
                wrefresh(ms->pktlist);
                if (ms->subwindow.win) {
                    refresh_pad(ms, -scroll, ms->scrollx);
                }
            } else {
                ms->top += num_lines;
                wscrl(ms->pktlist, num_lines);
                print_lines(ms, ms->top, ms->top + num_lines, 0);
                show_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
                wrefresh(ms->pktlist);
                if (ms->subwindow.win) {
                    refresh_pad(ms, -num_lines, ms->scrollx);
                }
            }
        }
    } else { /* scroll page up */
        if (vector_size(packets) <= abs(num_lines) || ms->top == 0) {
            remove_selectionbar(ms, ms->pktlist, ms->selection_line, A_NORMAL);
            ms->selection_line = 0;
            show_selectionbar(ms, ms->pktlist, 0, A_NORMAL);
            wrefresh(ms->pktlist);
            if (ms->subwindow.win) {
                refresh_pad(ms, 0, ms->scrollx);
            }
        } else {
            remove_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
            ms->selection_line += num_lines;
            if (ms->top + num_lines < 0) {
                wscrl(ms->pktlist, -ms->top);
                if (ms->selection_line < 0) {
                    ms->selection_line = 0;
                }
                print_lines(ms, 0, -num_lines, 0);
                show_selectionbar(ms, ms->pktlist, ms->selection_line, A_NORMAL);
                wrefresh(ms->pktlist);
                if (ms->subwindow.win) {
                    refresh_pad(ms, ms->top, ms->scrollx);
                }
                ms->top = 0;
            } else {
                wscrl(ms->pktlist, num_lines);
                ms->top += num_lines;
                print_lines(ms, ms->top, ms->top - num_lines, 0);
                show_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
                wrefresh(ms->pktlist);
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
        ms->selection_line = ms->top;
        show_selectionbar(ms, ms->pktlist, 0, A_NORMAL);
        wrefresh(ms->pktlist);
    } else {
        int my;

        my = getmaxy(ms->pktlist);
        if (ms->subwindow.win) {
            delete_subwindow(ms);
            ms->main_line.selected = false;
        }
        if (ms->outy >= my && ctx->capturing) {
            goto_end(ms);
        } else {
            remove_selectionbar(ms, ms->pktlist, ms->selection_line - ms->top, A_NORMAL);
        }
        interactive = false;
        wrefresh(ms->pktlist);
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
                    printnlw(ms->pktlist, buffer, n, y++, 0, ms->scrollx);
                } else {
                    y++;
                }
            } else {
                printnlw(ms->pktlist, buffer, strlen(buffer), y++, 0, ms->scrollx);
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
            screen_line = ms->selection_line - ms->top;
            subline = screen_line - ms->subwindow.top;
            data = GET_DATA(ms->lvw, subline);
            SET_EXPANDED(ms->lvw, subline, !GET_EXPANDED(ms->lvw, subline));
            if (data >= 0 && data < NUM_LAYERS) {
                selected[data] = GET_EXPANDED(ms->lvw, subline);
            }
            p = vector_get_data(packets, prev_selection);
            print_protocol_information(ms, p, prev_selection);
            return;
        }
    }
    screen_line = ms->selection_line + ms->scrolly - ms->top;
    if (screen_line == ms->main_line.line_number) {
        ms->main_line.selected = !ms->main_line.selected;
    } else {
        ms->main_line.selected = true;

        /* the index to the selected line needs to be adjusted in case of an
           open subwindow */
        if (ms->subwindow.win && subwindow_on_screen(ms) &&
            screen_line > ms->subwindow.top + ms->scrolly) {
            ms->main_line.line_number = screen_line - ms->subwindow.num_lines;
            ms->selection_line -= ms->subwindow.num_lines;
        } else {
            ms->main_line.line_number = screen_line;
        }
    }
    if (ms->main_line.selected) {
        p = vector_get_data(packets, ms->selection_line + ms->scrolly);
        if (view_mode == DECODED_VIEW) {
            add_elements(ms, p);
        }
        print_protocol_information(ms, p, ms->selection_line + ms->scrolly);
    } else {
        delete_subwindow(ms);
    }
    prev_selection = ms->selection_line + ms->scrolly;
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
        header = ADD_HEADER(ms->lvw, "Ethernet 802.3", selected[ETHERNET_LAYER], ETHERNET_LAYER);
    } else {
        header = ADD_HEADER(ms->lvw, "Ethernet II", selected[ETHERNET_LAYER], ETHERNET_LAYER);
    }
    add_ethernet_information(ms->lvw, header, p);
    if (p->perr == ARP_ERR || p->perr == IPv4_ERR || p->perr == IPv6_ERR) {
        header = ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
        add_hexdump(ms->lvw, header, hexmode, p->eth.data + ETH_HLEN, p->eth.payload_len);
    } else {
        if (p->eth.ethertype == ETH_P_ARP) {
            header = ADD_HEADER(ms->lvw, "Address Resolution Protocol (ARP)", selected[ARP], ARP);
            add_arp_information(ms->lvw, header, p);
        } else if (p->eth.ethertype == ETH_P_IP) {
            header = ADD_HEADER(ms->lvw, "Internet Protocol (IPv4)", selected[IP], IP);
            add_ipv4_information(ms->lvw, header, p->eth.ip);
            add_transport_elements(ms, p);
        } else if (p->eth.ethertype == ETH_P_IPV6) {
            header = ADD_HEADER(ms->lvw, "Internet Protocol (IPv6)", selected[IP], IP);
            add_ipv6_information(ms->lvw, header, p->eth.ipv6);
            add_transport_elements(ms, p);
        } else if (p->eth.ethertype <= ETH_802_3_MAX) {
            header = ADD_HEADER(ms->lvw, "Logical Link Control (LLC)", selected[LLC], LLC);
            add_llc_information(ms->lvw, header, p);
            if (p->perr == STP_ERR) {
                header = ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
                add_hexdump(ms->lvw, header, hexmode, p->eth.data + ETH_HLEN + LLC_HDR_LEN, LLC_PAYLOAD_LEN(p));
            } else {
                switch (get_eth802_type(p->eth.llc)) {
                case ETH_802_STP:
                    header = ADD_HEADER(ms->lvw, "Spanning Tree Protocol (STP)", selected[STP], STP);
                    add_stp_information(ms->lvw, header, p);
                    break;
                case ETH_802_SNAP:
                    header = ADD_HEADER(ms->lvw, "Subnetwork Access Protocol (SNAP)", selected[SNAP], SNAP);
                    add_snap_information(ms->lvw, header, p);
                    break;
                default:
                    header = ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
                    add_hexdump(ms->lvw, header, hexmode, p->eth.data + ETH_HLEN + LLC_HDR_LEN,
                                LLC_PAYLOAD_LEN(p));
                    break;
                }
            }
        } else { /* unknown network layer protocol */
            header = ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
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
        header = ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
        add_hexdump(ms->lvw, header, hexmode, get_ip_payload(p), IP_PAYLOAD_LEN(p));
    } else {
        switch (protocol) {
        case IPPROTO_TCP:
        {
            uint16_t len = TCP_PAYLOAD_LEN(p);

            header = ADD_HEADER(ms->lvw, "Transmission Control Protocol (TCP)",
                                selected[TRANSPORT], TRANSPORT);
            if (p->eth.ethertype == ETH_P_IP) {
                add_tcp_information(ms->lvw, header, &p->eth.ip->tcp);
                add_app_elements(ms, p, &p->eth.ip->tcp.data, len);
            } else {
                add_tcp_information(ms->lvw, header, &p->eth.ipv6->tcp);
                add_app_elements(ms, p, &p->eth.ipv6->tcp.data, len);
            }
            break;
        }
        case IPPROTO_UDP:
        {
            uint16_t len = UDP_PAYLOAD_LEN(p);

            header = ADD_HEADER(ms->lvw, "User Datagram Protocol (UDP)", selected[TRANSPORT], TRANSPORT);
            if (p->eth.ethertype == ETH_P_IP) {
                add_udp_information(ms->lvw, header, &p->eth.ip->udp);
                add_app_elements(ms, p, &p->eth.ip->udp.data, len);
            } else {
                add_udp_information(ms->lvw, header, &p->eth.ipv6->udp);
                add_app_elements(ms, p, &p->eth.ipv6->udp.data, len);
            }
            break;
        }
        case IPPROTO_ICMP:
            if (p->eth.ethertype == ETH_P_IP) {
                header = ADD_HEADER(ms->lvw, "Internet Control Message Protocol (ICMP)", selected[ICMP], ICMP);
                add_icmp_information(ms->lvw, header, &p->eth.ip->icmp);
            }
            break;
        case IPPROTO_IGMP:
            header = ADD_HEADER(ms->lvw, "Internet Group Management Protocol (IGMP)", selected[IGMP], IGMP);
            if (p->eth.ethertype == ETH_P_IP) {
                add_igmp_information(ms->lvw, header, &p->eth.ip->igmp);
            } else {
                add_igmp_information(ms->lvw, header, &p->eth.ipv6->igmp);
            }
            break;
        case IPPROTO_PIM:
            header = ADD_HEADER(ms->lvw, "Protocol Independent Multicast (PIM)", selected[PIM], PIM);
            if (p->eth.ethertype == ETH_P_IP) {
                add_pim_information(ms->lvw, header, &p->eth.ip->pim);
            } else {
                add_pim_information(ms->lvw, header, &p->eth.ipv6->pim);
            }
            break;
        default:
            /* unknown transport layer payload */
            header = ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
            add_hexdump(ms->lvw, header, hexmode, get_ip_payload(p), IP_PAYLOAD_LEN(p));
        }
    }
}

void add_app_elements(main_screen *ms, struct packet *p, struct application_info *adu, uint16_t len)
{
    list_view_header *header;

    switch (adu->utype) {
    case DNS:
    case MDNS:
    case LLMNR:
        header = ADD_HEADER(ms->lvw, "Domain Name System (DNS)", selected[APPLICATION], APPLICATION);
        add_dns_information(ms->lvw, header, adu->dns, adu->utype);
        break;
    case NBNS:
        header = ADD_HEADER(ms->lvw, "NetBIOS Name Service (NBNS)", selected[APPLICATION], APPLICATION);
        add_nbns_information(ms->lvw, header, adu->nbns);
        break;
    case NBDS:
        header = ADD_HEADER(ms->lvw, "NetBIOS Datagram Service (NBDS)", selected[APPLICATION], APPLICATION);
        add_nbds_information(ms->lvw, header, adu->nbds);
        break;
    case HTTP:
        header = ADD_HEADER(ms->lvw, "Hypertext Transfer Protocol (HTTP)", selected[APPLICATION], APPLICATION);
        add_http_information(ms->lvw, header, adu->http);
        break;
    case SSDP:
        header = ADD_HEADER(ms->lvw, "Simple Service Discovery Protocol (SSDP)", selected[APPLICATION], APPLICATION);
        add_ssdp_information(ms->lvw, header, adu->ssdp);
        break;
    case SNMP:
    case SNMPTRAP:
        header = ADD_HEADER(ms->lvw, "Simple Network Management Protocol (SNMP)", selected[APPLICATION], APPLICATION);
        add_snmp_information(ms->lvw, header, adu->snmp);
        break;
    default:
        if (len) {
            header = ADD_HEADER(ms->lvw, "Data", selected[APPLICATION], APPLICATION);
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
        RENDER(ms->lvw, ms->subwindow.win, ms->scrollx);
        subline = ms->selection_line - ms->top - ms->subwindow.top;
        if (inside_subwindow(ms)) {
            show_selectionbar(ms, ms->subwindow.win, subline, GET_ATTR(ms->lvw, subline));
        }
        refresh_pad(ms, 0, ms->scrollx);
    } else if (HEXDUMP_VIEW) {
        int subline;
        int num_lines = (hexmode == HEXMODE_NORMAL) ? (p->eth.payload_len + ETH_HLEN) / 16 + 3 :
            (p->eth.payload_len + ETH_HLEN) / 64 + 3;

        if (ms->lvw) {
            free_list_view(ms->lvw);
            ms->lvw = NULL;
        }
        create_subwindow(ms, num_lines, lineno);
        add_winhexdump(ms->subwindow.win, 0, 2, hexmode, p);
        subline = ms->selection_line - ms->top - ms->subwindow.top;
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

    getmaxyx(ms->pktlist, my, mx);
    start_line = lineno - ms->top;
    c = lineno + 1;
    if (num_lines >= my) num_lines = my - 1;

    /* if there is not enough space for the information to be printed, the
       screen needs to be scrolled to make room for all the lines */
    if (my - (start_line + 1) < num_lines) {
        ms->scrolly = num_lines - (my - (start_line + 1));
        wscrl(ms->pktlist, ms->scrolly);
        start_line -= ms->scrolly;
        ms->selection_line -= ms->scrolly;
    }

    /* make space for protocol specific information */
    ms->subwindow.win = newpad(num_lines, mx);
    ms->subwindow.top = start_line + 1;
    ms->subwindow.num_lines = num_lines;
    ms->subwindow.lineno = lineno;
    wmove(ms->pktlist, start_line + 1, 0);
    wclrtobot(ms->pktlist); /* clear everything below selection bar */
    ms->outy = start_line + 1;

    if (!ms->scrolly) {
        ms->outy += print_lines(ms, c, ms->top + my, ms->outy);
    } else {
        ms->outy += num_lines;
    }
    wrefresh(ms->pktlist);
}

void delete_subwindow(main_screen *ms)
{
    int my;
    int screen_line;

    my = getmaxy(ms->pktlist);
    screen_line = ms->selection_line - ms->top;
    delwin(ms->subwindow.win);
    ms->subwindow.win = NULL;
    ms->subwindow.num_lines = 0;
    werase(ms->pktlist);

    /*
     * Print the entire screen. This can be optimized to just print the lines
     * that are below the selected line
     */
    ms->outy = print_lines(ms, ms->top, ms->top + my, 0);

    if (ms->scrolly) {
        screen_line += ms->scrolly;
        ms->selection_line += ms->scrolly;
        ms->scrolly = 0;
    }
    show_selectionbar(ms, ms->pktlist, screen_line, A_NORMAL);
    wrefresh(ms->pktlist);
}

/* Returns whether the selection line is inside the subwindow or not */
bool inside_subwindow(main_screen *ms)
{
    int subline = ms->selection_line - ms->top - ms->subwindow.top;

    return ms->subwindow.win && subline >= 0 && subline < ms->subwindow.num_lines;
}

/* Returns whether the subwindow is shown on screen or not */
bool subwindow_on_screen(main_screen *ms)
{
    int my;

    my = getmaxy(ms->pktlist);
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

    getmaxyx(ms->pktlist, my, mx);
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
     int screen_line = ms->selection_line - ms->top;
     int subline = screen_line - ms->subwindow.top;

     if (c == KEY_UP) {
         if (screen_line == ms->subwindow.top + ms->subwindow.num_lines) {
             remove_selectionbar(ms, ms->pktlist, screen_line, A_NORMAL);
         } else {
             remove_selectionbar(ms, ms->subwindow.win, subline, ms->lvw ? GET_ATTR(ms->lvw, subline) : A_NORMAL);
         }
         if (subline == 0) {
             show_selectionbar(ms, ms->pktlist, screen_line - 1, A_NORMAL);
         } else {
             show_selectionbar(ms, ms->subwindow.win, subline - 1, ms->lvw ? GET_ATTR(ms->lvw, subline - 1) : A_NORMAL);
         }
     } else if (c == KEY_DOWN) {
         if (subline == -1) {
             remove_selectionbar(ms, ms->pktlist, screen_line, A_NORMAL);
         } else {
             remove_selectionbar(ms, ms->subwindow.win, subline, ms->lvw ? GET_ATTR(ms->lvw, subline) : A_NORMAL);
         }
         if (screen_line + 1 == ms->subwindow.top + ms->subwindow.num_lines) {
             show_selectionbar(ms, ms->pktlist, screen_line + 1, A_NORMAL);
         } else {
             show_selectionbar(ms, ms->subwindow.win, subline + 1, ms->lvw ? GET_ATTR(ms->lvw, subline + 1) : A_NORMAL);
         }
     }
}
