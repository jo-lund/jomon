#include <string.h>
#include <signal.h>
#include <linux/igmp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>
#include "layout.h"
#include "protocols.h"
#include "../list.h"
#include "../error.h"
#include "../util.h"
#include "../vector.h"
#include "../decoder/decoder.h"
#include "../stack.h"
#include "list_view.h"
#include "layout_int.h"
#include "stat_screen.h"
#include "../signal.h"

#define HEADER_HEIGHT 4
#define STATUS_HEIGHT 1

#define SHOW_SELECTIONBAR(l, a) (mvwchgat(wmain->pktlist, l, 0, -1, a, 1, NULL))
#define REMOVE_SELECTIONBAR(l, a) (mvwchgat(wmain->pktlist, l, 0, -1, a, 0, NULL))

typedef struct {
    struct line_info {
        int line_number;
        bool selected;
    } main_line;

    struct subwin_info {
        WINDOW *win;
        unsigned int top; /* index to the first line in the subwindow relative to the
                             main window */
        unsigned int num_lines;
    } subwindow;

    WINDOW *header;
    WINDOW *status;
    WINDOW *pktlist;
    int selection_line; /* index to the selection bar */
    list_view *lvw;

    /* next available line, i.e. outy - 1 is the last line printed on the screen */
    int outy;

    /*
     * Index to top of main window. The main screen will be between top + maximum
     * number of lines of the main window, i.e. getmaxy(main_window->win).
     */
    int top;

    /*
     * the number of lines that need to be scrolled to show all the information
     * when inspecting a packet
     */
    int scrolly;

    int scrollx; /* the amount scrolled on the x-axis */
} main_screen;

extern vector_t *packets;
extern main_context ctx;
screen *screens[NUM_SCREENS];
bool numeric = true;
static bool selected[NUM_LAYERS]; // TODO: need to handle this differently
static main_screen *wmain;
static bool capturing = true;
static bool interactive = false;
static bool input_mode = false;
static _stack_t *screen_stack;

static main_screen *create_main_screen(int nlines, int ncols);
static void free_main_screen(main_screen *mw);
static void set_interactive(bool interactive_mode, int num_lines);
static bool check_line();
static void handle_keydown(int num_lines);
static void handle_keyup(int num_lines);
static void scroll_page(int num_lines);
static void scroll_window();
static int print_lines(int from, int to, int y);
static void print(char *buf);
static void print_header();
static void print_status();
static void print_selected_packet();
static void print_protocol_information(struct packet *p, int lineno);
static void goto_line(int c);
static void goto_end();
static void print_help();

/* Handles subwindow layout */
static void create_subwindow(int num_lines, int lineno);
static void delete_subwindow();
static bool update_subwin_selection();
static void add_elements(struct packet *p);
static void add_transport_elements(struct packet *p);
static void add_app_elements(struct packet *p, struct application_info *info, uint16_t len);

void init_ncurses()
{
    initscr(); /* initialize curses mode */
    cbreak(); /* disable line buffering */
    noecho();
    curs_set(0); /* make the cursor invisible */
    use_default_colors();
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_CYAN);
    init_pair(2, COLOR_BLACK, COLOR_CYAN);
    init_pair(3, COLOR_CYAN, -1);
    init_pair(4, COLOR_GREEN, -1);
    set_escdelay(25); /* set escdelay to 25 ms */
    init_publisher();
}

void end_ncurses()
{
    free_main_screen(wmain);
    for (int i = 0; i < NUM_SCREENS; i++) {
        if (screens[i]) {
            free(screens[i]);
        }
    }
    endwin(); /* end curses mode */
}

void create_layout()
{
    int mx, my;

    getmaxyx(stdscr, my, mx);
    wmain = create_main_screen(my, mx);
    nodelay(wmain->pktlist, TRUE); /* input functions must be non-blocking */
    keypad(wmain->pktlist, TRUE);
    print_header();
    print_status();
    scrollok(wmain->pktlist, TRUE); /* enable scrolling */
    screen_stack = stack_init(NUM_SCREENS);
    memset(screens, 0, NUM_SCREENS * sizeof(screens));
}

main_screen *create_main_screen(int nlines, int ncols)
{
    main_screen *wm = malloc(sizeof(main_screen));

    wm->outy = 0;
    wm->selection_line = 0;
    wm->top = 0;
    wm->scrolly = 0;
    wm->scrollx = 0;
    wm->lvw = NULL;
    wm->header = newwin(HEADER_HEIGHT, ncols, 0, 0);
    wm->pktlist = newwin(nlines - HEADER_HEIGHT - STATUS_HEIGHT, ncols, HEADER_HEIGHT, 0);
    wm->status = newwin(STATUS_HEIGHT, ncols, nlines - STATUS_HEIGHT, 0);
    return wm;
}

void free_main_screen(main_screen *mw)
{
    if (mw->subwindow.win) {
        delwin(mw->subwindow.win);
    }
    delwin(mw->header);
    delwin(mw->pktlist);
    delwin(mw->status);
    free(mw);
}

/* scroll the window if necessary */
void scroll_window()
{
    int my;

    my = getmaxy(wmain->pktlist);
    if (wmain->outy >= my) {
        wmain->outy = my - 1;
        scroll(wmain->pktlist);
        wmain->top++;
    }
}

void get_input()
{
    int c = 0;
    int my;
    screen *s = stack_top(screen_stack);

    if (s) {
        if (s->type == STAT_SCREEN) {
            ss_handle_input();
        } else {
            pop_screen();
        }
        return;
    }

    my = getmaxy(wmain->pktlist);
    c = wgetch(wmain->pktlist);
    switch (c) {
    case 'i':
        set_interactive(!interactive, my);
        break;
    case KEY_F(10):
    case 'q':
        finish();
        break;
    case 'n':
        numeric = !numeric;
        break;
    case KEY_UP:
        handle_keyup(my);
        break;
    case KEY_DOWN:
        handle_keydown(my);
        break;
    case KEY_LEFT:
        if (wmain->scrollx) {
            werase(wmain->pktlist);
            wmain->scrollx -= 4;
            print_lines(wmain->top, wmain->top + my, 0);
            SHOW_SELECTIONBAR(wmain->selection_line - wmain->top, A_NORMAL);
            wrefresh(wmain->pktlist);
        }
        break;
    case KEY_RIGHT:
        werase(wmain->pktlist);
        wmain->scrollx += 4;
        print_lines(wmain->top, wmain->top + my, 0);
        SHOW_SELECTIONBAR(wmain->selection_line - wmain->top, A_NORMAL);
        wrefresh(wmain->pktlist);
        break;
    case KEY_ENTER:
    case '\n':
        if (input_mode) {
            goto_line(c);
        } else if (interactive) {
            print_selected_packet();
        }
        break;
    case KEY_ESC:
        if (input_mode) {
            curs_set(0);
            werase(wmain->status);
            print_status();
            input_mode = false;
        } else if (interactive) {
            set_interactive(false, my);
        }
        break;
    case ' ':
    case KEY_NPAGE:
        scroll_page(my);
        break;
    case 'b':
    case KEY_PPAGE:
        scroll_page(-my);
        break;
    case KEY_HOME:
        if (interactive) {
            int my = getmaxy(wmain->pktlist);

            werase(wmain->pktlist);
            print_lines(0, my, 0);
            wmain->selection_line = 0;
            wmain->top = 0;
            SHOW_SELECTIONBAR(0, A_NORMAL);
            wrefresh(wmain->pktlist);
        }
        break;
    case KEY_END:
        if (interactive) {
            if (wmain->outy >= my) {
                goto_end();
            }
            REMOVE_SELECTIONBAR(wmain->selection_line - wmain->top, A_NORMAL);
            wmain->selection_line = vector_size(packets) - 1;
            SHOW_SELECTIONBAR(wmain->selection_line - wmain->top, A_NORMAL);
            wrefresh(wmain->pktlist);
        }
        break;
    case KEY_F(1):
        push_screen(HELP_SCREEN);
        break;
    case 'g':
        if (!interactive) return;
        input_mode = !input_mode;
        if (input_mode) {
            werase(wmain->status);
            mvwprintw(wmain->status, 0, 0, "Go to line: ");
            curs_set(1);
        } else {
            curs_set(0);
            werase(wmain->status);
            print_status();
        }
        wrefresh(wmain->status);
        break;
    case 's':
        push_screen(STAT_SCREEN);
        break;
    default:
        if (input_mode) {
            goto_line(c);
        }
        break;
    }
}

void print_header()
{
    int y = 0;
    char addr[INET_ADDRSTRLEN];

    if (ctx.filename) {
        printat(wmain->header, y, 0, COLOR_PAIR(3) | A_BOLD, "Filename");
        wprintw(wmain->header, ": %s", ctx.filename);
    } else {
        printat(wmain->header, y, 0, COLOR_PAIR(3) | A_BOLD, "Listening on device");
        wprintw(wmain->header, ": %s", ctx.device);
    }
    inet_ntop(AF_INET, &local_addr->sin_addr, addr, sizeof(addr));
    printat(wmain->header, ++y, 0, COLOR_PAIR(3) | A_BOLD, "Local address");
    wprintw(wmain->header, ": %s", addr);
    y += 2;
    mvwprintw(wmain->header, y, 0, "Number");
    mvwprintw(wmain->header, y, NUM_WIDTH, "Source");
    mvwprintw(wmain->header, y, ADDR_WIDTH + NUM_WIDTH, "Destination");
    mvwprintw(wmain->header, y, 2 * ADDR_WIDTH + NUM_WIDTH, "Protocol");
    mvwprintw(wmain->header, y, 2 * ADDR_WIDTH + PROT_WIDTH + NUM_WIDTH, "Info");
    mvwchgat(wmain->header, y, 0, -1, A_STANDOUT, 0, NULL);
    wrefresh(wmain->header);
}

void print_status()
{
    mvwprintw(wmain->status, 0, 0, "F1");
    printat(wmain->status, -1, -1, COLOR_PAIR(2), "%-8s", "Help");
    wprintw(wmain->status, "F2");
    printat(wmain->status, -1, -1, COLOR_PAIR(2), "%-8s", "Start");
    wprintw(wmain->status, "F3");
    printat(wmain->status, -1, -1, COLOR_PAIR(2), "%-8s", "Stop");
    wprintw(wmain->status, "F4");
    printat(wmain->status, -1, -1, COLOR_PAIR(2), "%-8s", "Load");
    wprintw(wmain->status, "F5");
    printat(wmain->status, -1, -1, COLOR_PAIR(2), "%-8s", "Save");
    wprintw(wmain->status, "F6");
    printat(wmain->status, -1, -1, COLOR_PAIR(2), "%-8s", "Views");
    wprintw(wmain->status, "F10");
    printat(wmain->status, -1, -1, COLOR_PAIR(2), "%-8s", "Quit");
    wrefresh(wmain->status);
}

void print_help()
{
    int y = 0;
    WINDOW *win = screens[HELP_SCREEN]->win;

    wprintw(win, "Monitor 0.0.1 (c) 2017 John Olav Lund");
    mvwprintw(win, ++y, 0, "");
    mvwprintw(win, ++y, 0, "When a packet scan is active you can enter interactive mode " \
              "by pressing \'i\'. In interactive mode the packet scan will continue in the " \
              "background.");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, COLOR_PAIR(4) | A_BOLD, "General keyboard shortcuts");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "F1");
    wprintw(win, ": Show help");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "F10 q");
    wprintw(win, ": Quit");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, COLOR_PAIR(4) | A_BOLD, "Main screen keyboard shortcuts");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "i");
    wprintw(win, ": Enter interactive mode");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "s");
    wprintw(win, ": Show statistics screen");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "F2");
    wprintw(win, ": Start packet scan");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "F3");
    wprintw(win, ": Stop packet scan");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "F4");
    wprintw(win, ": Load file in pcap format");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "F5");
    wprintw(win, ": Save file in pcap format");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "F6");
    wprintw(win, ": Change view");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, COLOR_PAIR(4) | A_BOLD, "Keyboard shortcuts in interactive mode");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "Arrows");
    wprintw(win, ": Scroll the packet list");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "Space pgdown");
    wprintw(win, ": Scroll page down");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "b pgup");
    wprintw(win, ": Scroll page up");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "Home End");
    wprintw(win, ": Go to first/last page");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "g");
    wprintw(win, ": Go to line");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "Enter");
    wprintw(win, ": Inspect packet");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "Esc i");
    wprintw(win, ": Quit interactive mode");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, COLOR_PAIR(4) | A_BOLD, "Statistics screen keyboard shortcuts");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "b B");
    wprintw(win, ": Use kilobits/kilobytes");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "m M");
    wprintw(win, ": Use megabits/megabytes");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "p");
    wprintw(win, ": Show/hide packet statistics");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "c");
    wprintw(win, ": Clear statistics");
    printat(win, ++y, 0, COLOR_PAIR(3) | A_BOLD, "%12s", "Esc x");
    wprintw(win, ": Exit statistics screen");
}

void goto_line(int c)
{
    static uint32_t num = 0;

    if (isdigit(c)) {
        waddch(wmain->status, c);
        num = num * 10 + c - '0';
    } else if (c == KEY_BACKSPACE) {
        int x, y;

        getyx(wmain->status, y, x);
        if (x >= 13) {
            mvwdelch(wmain->status, y, x - 1);
            num /= 10;
        }
    } else if (num && (c == '\n' || c == KEY_ENTER)) {
        if (num > vector_size(packets)) return;

        int my;

        my = getmaxy(wmain->pktlist);
        if (num >= wmain->top && num < wmain->top + my) {
            mvwchgat(wmain->pktlist, wmain->selection_line, 0, -1, A_NORMAL, 0, NULL);
            wmain->selection_line = num - 1;
            mvwchgat(wmain->pktlist, wmain->selection_line, 0, -1, A_NORMAL, 1, NULL);
        } else {
            werase(wmain->pktlist);
            mvwchgat(wmain->pktlist, wmain->selection_line, 0, -1, A_NORMAL, 0, NULL);
            if (num + my - 1 > vector_size(packets)) {
                print_lines(vector_size(packets) - my, vector_size(packets), 0);
                wmain->top = vector_size(packets) - my;
                wmain->selection_line = num - 1;
                mvwchgat(wmain->pktlist, num - 1 - wmain->top, 0, -1, A_NORMAL, 1, NULL);
            } else {
                print_lines(num - 1, num + my - 1, 0);
                wmain->selection_line = wmain->top = num - 1;
                mvwchgat(wmain->pktlist, 0, 0, -1, A_NORMAL, 1, NULL);
            }
        }
        wrefresh(wmain->pktlist);
        curs_set(0);
        werase(wmain->status);
        input_mode = false;
        num = 0;
        print_status();

    }
    wrefresh(wmain->status);
}

void goto_end()
{
    int c = vector_size(packets) - 1;
    int my = getmaxy(wmain->pktlist);

    werase(wmain->pktlist);

    /* print the new lines stored in vector from bottom to top of screen */
    for (int i = my - 1; i >= 0; i--, c--) {
        struct packet *p;
        char buffer[MAXLINE];

        p = vector_get_data(packets, c);
        print_buffer(buffer, MAXLINE, p);
        printnlw(wmain->pktlist, buffer, strlen(buffer), i, 0, wmain->scrollx);
    }
    wmain->top = c + 1;
}

/*
 * Checks if there still are lines to highlight when moving the selection bar
 * down. Returns true if that's the case.
 */
bool check_line()
{
    int num_lines = 0;

    if (wmain->subwindow.win) {
        num_lines += wmain->subwindow.num_lines - 1;
    }
    if (wmain->selection_line < vector_size(packets) + num_lines - 1) {
        return true;
    }
    return false;
}

void handle_keyup(int num_lines)
{
    if (!interactive) {
        set_interactive(true, num_lines);
    }

    /* scroll screen if the selection bar is at the top */
    if (wmain->top && wmain->selection_line == wmain->top) {
        struct packet *p = vector_get_data(packets, --wmain->selection_line);

        wmain->top--;
        if (wmain->subwindow.win) {
            wmain->subwindow.top++;
            wmain->main_line.line_number++;
        }
        if (p) {
            char line[MAXLINE];

            wscrl(wmain->pktlist, -1);
            print_buffer(line, MAXLINE, p);
            printnlw(wmain->pktlist, line, strlen(line), 0, 0, wmain->scrollx);

            /* deselect previous line and highlight next at top */
            mvwchgat(wmain->pktlist, 1, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain->pktlist, 0, 0, -1, A_NORMAL, 1, NULL);
        }
    } else if (wmain->selection_line > 0) {
        int screen_line = wmain->selection_line - wmain->top;

        /* deselect previous line and highlight next */
        if (wmain->subwindow.win && screen_line >= wmain->subwindow.top &&
            screen_line < wmain->subwindow.top + wmain->subwindow.num_lines) {
            int subline = screen_line - wmain->subwindow.top;

            mvwchgat(wmain->pktlist, screen_line, 0, -1, GET_ATTR(wmain->lvw, subline), 0, NULL);
            mvwchgat(wmain->pktlist, screen_line - 1, 0, -1, subline == 0 ? A_NORMAL :
                     GET_ATTR(wmain->lvw, subline - 1), 1, NULL);
        } else {
            mvwchgat(wmain->pktlist, screen_line, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain->pktlist, screen_line - 1, 0, -1, A_NORMAL, 1, NULL);
        }
        wmain->selection_line--;
    }
    wrefresh(wmain->pktlist);
}

void handle_keydown(int num_lines)
{
    if (!check_line()) return;

    if (!interactive) {
        set_interactive(true, num_lines);
    }

    /* scroll screen if the selection bar is at the bottom */
    if (wmain->selection_line - wmain->top == num_lines - 1) {
        struct packet *p = vector_get_data(packets, ++wmain->selection_line);

        wmain->top++;
        if (wmain->subwindow.win) {
            wmain->subwindow.top--;
            wmain->main_line.line_number--;
        }
        if (p) {
            char line[MAXLINE];

            wscrl(wmain->pktlist, 1);
            print_buffer(line, MAXLINE, p);
            printnlw(wmain->pktlist, line, strlen(line), num_lines - 1, 0, wmain->scrollx);

            /* deselect previous line and highlight next line at bottom */
            mvwchgat(wmain->pktlist, num_lines - 2, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain->pktlist, num_lines - 1, 0, -1, A_NORMAL, 1, NULL);
        }
    } else {
        int screen_line = wmain->selection_line - wmain->top;

        /* deselect previous line and highlight next */
        if (wmain->subwindow.win && screen_line + 1 >= wmain->subwindow.top &&
            screen_line + 1 < wmain->subwindow.top + wmain->subwindow.num_lines) {
            int subline = screen_line - wmain->subwindow.top;

            mvwchgat(wmain->pktlist, screen_line, 0, -1, subline == -1 ? A_NORMAL :
                     GET_ATTR(wmain->lvw, subline), 0, NULL);
            mvwchgat(wmain->pktlist, screen_line + 1, 0, -1, GET_ATTR(wmain->lvw, subline + 1), 1, NULL);
        } else {
            mvwchgat(wmain->pktlist, screen_line, 0, -1, A_NORMAL, 0, NULL);
            mvwchgat(wmain->pktlist, screen_line + 1, 0, -1, A_NORMAL, 1, NULL);
        }
        wmain->selection_line++;
    }
    wrefresh(wmain->pktlist);
}

void scroll_page(int num_lines)
{
    if (!interactive) {
        set_interactive(true, num_lines);
    }
    if (num_lines > 0) { /* scroll page down */
        if (vector_size(packets) <= num_lines) {
            mvwchgat(wmain->pktlist, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 0, NULL);
            wmain->selection_line = vector_size(packets) - 1;
            mvwchgat(wmain->pktlist, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 1, NULL);
        } else {
            int bottom = wmain->top + num_lines - 1;

            mvwchgat(wmain->pktlist, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 0, NULL);
            wmain->selection_line += num_lines;
            if (bottom + num_lines > vector_size(packets) - 1) {
                int scroll = vector_size(packets) - bottom - 1;

                wscrl(wmain->pktlist, scroll);
                wmain->top += scroll;
                if (wmain->subwindow.win) {
                    wmain->subwindow.top -= scroll;
                    wmain->main_line.line_number -= scroll;
                }
                if (wmain->selection_line >= vector_size(packets)) {
                    wmain->selection_line = vector_size(packets) - 1;
                }
                print_lines(bottom + 1, vector_size(packets), vector_size(packets) - scroll - wmain->top);
            } else {
                wmain->top += num_lines;
                if (wmain->subwindow.win) {
                    wmain->subwindow.top -= num_lines;
                    wmain->main_line.line_number -= num_lines;
                }
                wscrl(wmain->pktlist, num_lines);
                print_lines(wmain->top, wmain->top + num_lines, 0);
            }
            mvwchgat(wmain->pktlist, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 1, NULL);
        }
    } else { /* scroll page up */
        if (vector_size(packets) <= abs(num_lines)) {
            mvwchgat(wmain->pktlist, wmain->selection_line, 0, -1, A_NORMAL, 0, NULL);
            wmain->selection_line = 0;
            mvwchgat(wmain->pktlist, 0, 0, -1, A_NORMAL, 1, NULL);
        } else {
            mvwchgat(wmain->pktlist, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 0, NULL);
            wmain->selection_line += num_lines;
            if (wmain->top + num_lines < 0) {
                wscrl(wmain->pktlist, -wmain->top);
                wmain->top = 0;
                if (wmain->selection_line < 0) {
                    wmain->selection_line = 0;
                }
                print_lines(wmain->top, wmain->top - num_lines, 0);
            } else {
                wscrl(wmain->pktlist, num_lines);
                wmain->top += num_lines;
                if (wmain->subwindow.win) {
                    wmain->subwindow.top -= num_lines;
                    wmain->main_line.line_number -= num_lines;
                }
                print_lines(wmain->top, wmain->top - num_lines, 0);
            }
            mvwchgat(wmain->pktlist, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 1, NULL);
        }
    }
    wrefresh(wmain->pktlist);
}

void set_interactive(bool interactive_mode, int num_lines)
{
    if (!vector_size(packets)) return;

    if (interactive_mode) {
        interactive = true;
        wmain->selection_line = wmain->top;

        /* print selection bar */
        mvwchgat(wmain->pktlist, 0, 0, -1, A_NORMAL, 1, NULL);
        wrefresh(wmain->pktlist);
    } else {
        if (wmain->subwindow.win) {
            delete_subwindow();
            wmain->main_line.selected = false;
        }
        if (wmain->outy >= num_lines && capturing) {
            goto_end();
        } else {
            /* remove selection bar */
            mvwchgat(wmain->pktlist, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 0, NULL);
        }
        interactive = false;
        wrefresh(wmain->pktlist);
    }
}

/*
 * Prints lines in the interval [from, to). 'y' specifies where on the screen it
 * will start to print. Returns how many lines are actually printed.
 */
int print_lines(int from, int to, int y)
{
    int c = 0;

    while (from < to) {
        struct packet *p;
        char buffer[MAXLINE];

        p = vector_get_data(packets, from);
        if (!p) break;
        print_buffer(buffer, MAXLINE, p);
        if (wmain->scrollx) {
            int n = strlen(buffer);

            if (wmain->scrollx < n) {
                printnlw(wmain->pktlist, buffer, n, y++, 0, wmain->scrollx);
            } else {
                y++;
            }
        } else {
            printnlw(wmain->pktlist, buffer, strlen(buffer), y++, 0, wmain->scrollx);
        }
        from++;
        c++;
    }
    return c;
}

void print_packet(struct packet *p)
{
    char buf[MAXLINE];

    print_buffer(buf, MAXLINE, p);
    print(buf);
}

void print_file()
{
    int my = getmaxy(wmain->pktlist);

    capturing = false;
    for (int i = 0; i < vector_size(packets) && i < my; i++) {
        print_packet(vector_get_data(packets, i));
    }
    set_interactive(true, -1);
}

/* write buffer to standard output */
void print(char *buf)
{
    int my;

    my = getmaxy(wmain->pktlist);
    if (!interactive || (interactive && wmain->outy < my)) {
        scroll_window();
        printnlw(wmain->pktlist, buf, strlen(buf), wmain->outy, 0, wmain->scrollx);
        wmain->outy++;
        if (stack_empty(screen_stack)) {
            wrefresh(wmain->pktlist);
        }
    }
}

/*
 * Print more information about a packet when selected. This will print more
 * details about the specific protocol headers and payload.
 */
void print_selected_packet()
{
    int screen_line;
    struct packet *p;
    static int prev_selection = -1;

    if (prev_selection >= 0 && wmain->subwindow.win) {
        bool inside_subwin;

        inside_subwin = update_subwin_selection();
        if (inside_subwin) {
            p = vector_get_data(packets, prev_selection);
            print_protocol_information(p, prev_selection);
            return;
        }
    }
    screen_line = wmain->selection_line + wmain->scrolly - wmain->top;
    if (screen_line == wmain->main_line.line_number) {
        wmain->main_line.selected = !wmain->main_line.selected;
    } else {
        wmain->main_line.selected = true;

        /* the index to the selected line needs to be adjusted in case of an
           open wmain->subwindow */
        if (wmain->subwindow.win && screen_line > wmain->subwindow.top + wmain->scrolly) {
            wmain->main_line.line_number = screen_line - wmain->subwindow.num_lines;
            wmain->selection_line -= wmain->subwindow.num_lines;
        } else {
            wmain->main_line.line_number = screen_line;
        }
    }
    if (wmain->main_line.selected) {
        p = vector_get_data(packets, wmain->selection_line + wmain->scrolly);
        add_elements(p);
        print_protocol_information(p, wmain->selection_line + wmain->scrolly);
    } else {
        delete_subwindow();
    }
    prev_selection = wmain->selection_line + wmain->scrolly;
}

void add_elements(struct packet *p)
{
    list_view_item *header;

    if (wmain->lvw) {
        free_list_view(wmain->lvw);
    }
    wmain->lvw = create_list_view();

    /* inspect packet and add packet headers as elements to the list view */
    if (p->eth.ethertype < ETH_P_802_3_MIN) {
        header = ADD_HEADER(wmain->lvw, "Ethernet 802.3", selected[ETHERNET_LAYER], ETHERNET_LAYER);
    } else {
        header = ADD_HEADER(wmain->lvw, "Ethernet II", selected[ETHERNET_LAYER], ETHERNET_LAYER);
    }
    add_ethernet_information(wmain->lvw, header, p);
    if (p->eth.ethertype == ETH_P_ARP) {
        header = ADD_HEADER(wmain->lvw, "Address Resolution Protocol (ARP)", selected[ARP], ARP);
        add_arp_information(wmain->lvw, header, p);
    } else if (p->eth.ethertype == ETH_P_IP) {
        header = ADD_HEADER(wmain->lvw, "Internet Protocol (IPv4)", selected[IP], IP);
        add_ipv4_information(wmain->lvw, header, p->eth.ip);
        add_transport_elements(p);
    } else if (p->eth.ethertype == ETH_P_IPV6) {
        header = ADD_HEADER(wmain->lvw, "Internet Protocol (IPv6)", selected[IP], IP);
        add_ipv6_information(wmain->lvw, header, p->eth.ipv6);
        add_transport_elements(p);
    } else if (p->eth.ethertype < ETH_P_802_3_MIN) {
        header = ADD_HEADER(wmain->lvw, "Logical Link Control (LLC)", selected[LLC], LLC);
        add_llc_information(wmain->lvw, header, p);
        switch (get_eth802_type(p->eth.llc)) {
        case ETH_802_STP:
            header = ADD_HEADER(wmain->lvw, "Spanning Tree Protocol (STP)", selected[STP], STP);
            add_stp_information(wmain->lvw, header, p);
            break;
        case ETH_802_SNAP:
            header = ADD_HEADER(wmain->lvw, "Subnetwork Access Protocol (SNAP)", selected[SNAP], SNAP);
            add_snap_information(wmain->lvw, header, p);
            break;
        default:
            header = ADD_HEADER(wmain->lvw, "Unknown payload", selected[APPLICATION], APPLICATION);
            add_payload(wmain->lvw, header, p->eth.data + ETH_HLEN + LLC_HDR_LEN, LLC_PAYLOAD_LEN(p));
        }
    } else {
        header = ADD_HEADER(wmain->lvw, "Unknown payload", selected[APPLICATION], APPLICATION);
        add_payload(wmain->lvw, header, p->eth.data + ETH_HLEN, p->eth.payload_len);
    }
}

void add_transport_elements(struct packet *p)
{
    list_view_item *header;
    uint8_t protocol = (p->eth.ethertype == ETH_P_IP) ? p->eth.ip->protocol : p->eth.ipv6->next_header;

    switch (protocol) {
    case IPPROTO_TCP:
    {
        uint16_t len = TCP_PAYLOAD_LEN(p);

        header = ADD_HEADER(wmain->lvw, "Transmission Control Protocol (TCP)", selected[TRANSPORT], TRANSPORT);
        if (p->eth.ethertype == ETH_P_IP) {
            add_tcp_information(wmain->lvw, header, &p->eth.ip->tcp, selected[SUBLAYER]);
            add_app_elements(p, &p->eth.ip->tcp.data, len);
        } else {
            add_tcp_information(wmain->lvw, header, &p->eth.ipv6->tcp, selected[SUBLAYER]);
            add_app_elements(p, &p->eth.ipv6->tcp.data, len);
        }
        break;
    }
    case IPPROTO_UDP:
    {
        uint16_t len = UDP_PAYLOAD_LEN(p);

        header = ADD_HEADER(wmain->lvw, "User Datagram Protocol (UDP)", selected[TRANSPORT], TRANSPORT);
        if (p->eth.ethertype == ETH_P_IP) {
            add_udp_information(wmain->lvw, header, &p->eth.ip->udp);
            add_app_elements(p, &p->eth.ip->udp.data, len);
        } else {
            add_udp_information(wmain->lvw, header, &p->eth.ipv6->udp);
            add_app_elements(p, &p->eth.ipv6->udp.data, len);
        }
        break;
    }
    case IPPROTO_ICMP:
        if (p->eth.ethertype == ETH_P_IP) {
            header = ADD_HEADER(wmain->lvw, "Internet Control Message Protocol (ICMP)", selected[ICMP], ICMP);
            add_icmp_information(wmain->lvw, header, &p->eth.ip->icmp);
        }
        break;
    case IPPROTO_IGMP:
        header = ADD_HEADER(wmain->lvw, "Internet Group Management Protocol (IGMP)", selected[IGMP], IGMP);
        if (p->eth.ethertype == ETH_P_IP) {
            add_igmp_information(wmain->lvw, header, &p->eth.ip->igmp);
        } else {
            add_igmp_information(wmain->lvw, header, &p->eth.ipv6->igmp);
        }
        break;
    case IPPROTO_PIM:
        header = ADD_HEADER(wmain->lvw, "Protocol Independent Multicast (PIM)", selected[PIM], PIM);
        if (p->eth.ethertype == ETH_P_IP) {
            add_pim_information(wmain->lvw, header, &p->eth.ip->pim, selected[SUBLAYER]);
        } else {
            add_pim_information(wmain->lvw, header, &p->eth.ipv6->pim, selected[SUBLAYER]);
        }
        break;
    default:
        /* unknown transport layer payload */
        header = ADD_HEADER(wmain->lvw, "Unknown payload", selected[APPLICATION], APPLICATION);
        add_payload(wmain->lvw, header, get_ip_payload(p), IP_PAYLOAD_LEN(p));
    }
}

void add_app_elements(struct packet *p, struct application_info *info, uint16_t len)
{
    list_view_item *header;

    switch (info->utype) {
    case DNS:
    case MDNS:
        header = ADD_HEADER(wmain->lvw, "Domain Name System (DNS)", selected[APPLICATION], APPLICATION);
        add_dns_information(wmain->lvw, header, info->dns, selected[SUBLAYER]);
        break;
    case NBNS:
        header = ADD_HEADER(wmain->lvw, "NetBIOS Name Service (NBNS)", selected[APPLICATION], APPLICATION);
        add_nbns_information(wmain->lvw, header, info->nbns);
        break;
    case HTTP:
        header = ADD_HEADER(wmain->lvw, "Hypertext Transfer Protocol (HTTP)", selected[APPLICATION], APPLICATION);
        add_http_information(wmain->lvw, header, info->http);
        break;
    case SSDP:
        header = ADD_HEADER(wmain->lvw, "Simple Service Discovery Protocol (SSDP)", selected[APPLICATION], APPLICATION);
        add_ssdp_information(wmain->lvw, header, info->ssdp);
        break;
    default:
        if (len) {
            header = ADD_HEADER(wmain->lvw, "Unknown payload", selected[APPLICATION], APPLICATION);
            add_payload(wmain->lvw, header, get_adu_payload(p), len);
        }
        break;
    }
}

void print_protocol_information(struct packet *p, int lineno)
{
    /* Delete old subwindow. TODO: Don't use a subwindow for this */
    if (wmain->subwindow.win) {
        delete_subwindow();
    }

    /* print information in subwindow */
    create_subwindow(wmain->lvw->size + 1, lineno);
    RENDER(wmain->lvw, wmain->subwindow.win);

    int subline = wmain->selection_line - wmain->top - wmain->subwindow.top;
    if (subline >= 0) {
        mvwchgat(wmain->pktlist, wmain->selection_line - wmain->top, 0, -1, GET_ATTR(wmain->lvw, subline), 1, NULL);
    } else {
        mvwchgat(wmain->pktlist, wmain->selection_line - wmain->top, 0, -1, A_NORMAL, 1, NULL);
    }
    touchwin(wmain->pktlist);
    wrefresh(wmain->subwindow.win);
}

void create_subwindow(int num_lines, int lineno)
{
    int mx, my;
    int start_line;
    int c;

    getmaxyx(wmain->pktlist, my, mx);
    start_line = lineno - wmain->top;
    c = lineno + 1;
    if (num_lines >= my) num_lines = my - 1;

    /* if there is not enough space for the information to be printed, the
       screen needs to be scrolled to make room for all the lines */
    if (my - (start_line + 1) < num_lines) {
        wmain->scrolly = num_lines - (my - (start_line + 1));
        wscrl(wmain->pktlist, wmain->scrolly);
        start_line -= wmain->scrolly;
        wmain->selection_line -= wmain->scrolly;
        wrefresh(wmain->pktlist);
    }

    /* make space for protocol specific information */
    wmain->subwindow.win = derwin(wmain->pktlist, num_lines, mx, start_line + 1, 0);
    wmain->subwindow.top = start_line + 1;
    wmain->subwindow.num_lines = num_lines;
    wmove(wmain->pktlist, start_line + 1, 0);
    wclrtobot(wmain->pktlist); /* clear everything below selection bar */
    wmain->outy = start_line + num_lines + 1;

    if (!wmain->scrolly) {
        wmain->outy += print_lines(c, wmain->top + my, wmain->outy);
    }
    wrefresh(wmain->pktlist);
}

void delete_subwindow()
{
    int my;
    int screen_line;

    my = getmaxy(wmain->pktlist);
    screen_line = wmain->selection_line - wmain->top;
    delwin(wmain->subwindow.win);
    wmain->subwindow.win = NULL;
    wmain->subwindow.num_lines = 0;
    werase(wmain->pktlist);

    /*
     * Print the entire screen. This can be optimized to just print the lines
     * that are below the selected line
     */
    wmain->outy = print_lines(wmain->top, wmain->top + my, 0);

    if (wmain->scrolly) {
        screen_line += wmain->scrolly;
        wmain->selection_line += wmain->scrolly;
        wmain->scrolly = 0;
    }
    mvwchgat(wmain->pktlist, screen_line, 0, -1, A_NORMAL, 1, NULL);
    wrefresh(wmain->pktlist);
}

/*
 * Checks if wmain->selection_line is inside the subwindow, and if that's the case, updates the
 * selection status of the selectable subwindow line.
 *
 * Returns true if it's inside the subwindow, else false.
 */
bool update_subwin_selection()
{
    int screen_line;

    screen_line = wmain->selection_line - wmain->top;
    if (screen_line >= wmain->subwindow.top &&
        screen_line < wmain->subwindow.top + wmain->subwindow.num_lines) {
        int subline;
        int32_t data;

        subline = screen_line - wmain->subwindow.top;
        data = GET_DATA(wmain->lvw, subline);
        SET_EXPANDED(wmain->lvw, subline, !GET_EXPANDED(wmain->lvw, subline));
        if (data >= 0 && data < NUM_LAYERS) {
            selected[data] = GET_EXPANDED(wmain->lvw, subline);
        }
        return true;
    }
    return false;
}


void pop_screen()
{
    screen *scr = stack_pop(screen_stack);

    scr->focus = false;
    if (stack_empty(screen_stack)) {
        wgetch(wmain->pktlist); /* remove character from input queue */
        touchwin(wmain->pktlist);
        touchwin(wmain->status);
        touchwin(wmain->header);
        wnoutrefresh(wmain->pktlist);
        wnoutrefresh(wmain->header);
        wnoutrefresh(wmain->status);
        doupdate();
    } else {
        screen *s = stack_top(screen_stack);

        s->focus = true;
        publish();
        wgetch(s->win); /* remove character from input queue */
        touchwin(s->win);
        wrefresh(s->win);
    }
}

void push_screen(int scr)
{
    if (screens[scr]) {
        screen *s = stack_top(screen_stack);

        if (s) s->focus = false;
        stack_push(screen_stack, screens[scr]);
        screens[scr]->focus = true;
        publish();
        touchwin(screens[scr]->win);
        wrefresh(screens[scr]->win);
    } else {
        int mx, my;
        WINDOW *win;

        screens[scr] = malloc(sizeof(screen));
        getmaxyx(stdscr, my, mx);
        win = newwin(my, mx, 0, 0);
        screens[scr]->win = win;
        screens[scr]->type = scr;
        stack_push(screen_stack, screens[scr]);
        screens[scr]->focus = true;
        switch (scr) {
        case HELP_SCREEN:
            print_help();
            break;
        case STAT_SCREEN:
            nodelay(win, TRUE);
            keypad(win, TRUE);
            ss_init();
            ss_print();
            add_subscription(ss_changed);
            break;
        default:
            break;
        }
        wrefresh(win);
    }
}

void printat(WINDOW *win, int y, int x, int attrs, const char *fmt, ...)
{
    char buf[MAXLINE];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, MAXLINE - 1, fmt, ap);
    va_end(ap);
    wattron(win, attrs);
    if (y == -1 && x == -1) {
        waddstr(win, buf);
    } else {
        mvwprintw(win, y, x, "%s", buf);
    }
    wattroff(win, attrs);
}

void printnlw(WINDOW *win, char *str, int len, int y, int x, int scrollx)
{
    int mx = getmaxx(win);

    if (mx + scrollx - 1 < len) {
        str[mx + scrollx - 1] = '\0';
    }
    mvwprintw(win, y, x, "%s", str + scrollx);
}

bool is_capturing()
{
    return capturing;
}
