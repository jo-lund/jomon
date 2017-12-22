#include "layout.h"
#include "layout_int.h"
#include "protocols.h"
#include "main_screen.h"
#include "stat_screen.h"
#include "dialogue.h"
#include "../vector.h"
#include "../stack.h"
#include <string.h>

#define NUM_THEMES 3
#define NUM_COLOURS 8

#define COLOUR_IDX(f, b) ((b == -1) ? (f) + 1 : (b) + 1 + ((f) + 1) * NUM_COLOURS)

extern vector_t *packets;
extern main_context ctx;
publisher_t *screen_changed_publisher;
static struct screen *screen_cache[NUM_SCREENS];
static _stack_t *screen_stack;
static int theme;
static void help_screen_get_input(screen *s);
static void init_colours();

static int themes[NUM_THEMES][NUM_ELEMENTS] = {
    [DEFAULT] = {
        [HEADER]        = COLOUR_IDX(COLOR_BLACK, COLOR_WHITE),
        [HEADER_TXT]    = COLOUR_IDX(COLOR_GREEN, -1),
        [SUBHEADER_TXT] = COLOUR_IDX(COLOR_CYAN, -1),
        [STATUS_BUTTON] = COLOUR_IDX(COLOR_BLACK, COLOR_CYAN),
        [BUTTON]        = COLOUR_IDX(COLOR_BLACK, COLOR_WHITE),
        [DIALOGUE_BKGD] = COLOUR_IDX(COLOR_WHITE, COLOR_BLACK),
        [FD_LIST_BKGD]  = COLOUR_IDX(COLOR_CYAN, -1),
        [FD_INPUT_BKGD] = COLOUR_IDX(COLOR_BLACK, COLOR_WHITE),
        [FD_TEXT]       = COLOUR_IDX(COLOR_CYAN, -1),
        [DISABLE]       = COLOUR_IDX(COLOR_BLACK, -1),
        [FOCUS]         = COLOUR_IDX(COLOR_BLACK, COLOR_CYAN),
        [SELECTIONBAR]  = COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)
    }
};

void init_ncurses()
{
    main_screen *ms;

    initscr(); /* initialize curses mode */
    cbreak(); /* disable line buffering */
    noecho();
    curs_set(0);
    use_default_colors();
    start_color();
    init_colours();
    set_escdelay(25); /* set escdelay to 25 ms */
    screen_changed_publisher = publisher_init();
    screen_stack = stack_init(NUM_SCREENS);
    ms = main_screen_create();
    screen_cache_insert(MAIN_SCREEN, (screen *) ms);
    push_screen((screen *) ms);
}

void end_ncurses()
{
    screen_cache_clear();
    publisher_free(screen_changed_publisher);
    endwin();
}

screen *screen_create(screen_operations *defop)
{
    screen *s;

    s = malloc(sizeof(screen));
    s->op = defop;
    SCREEN_INIT(s);
    return s;
}

screen *screen_cache_get(enum screen_type type)
{
    if (screen_cache[type]) {
        return screen_cache[type];
    }
    return NULL;
}

void screen_init(screen *s)
{
    int my, mx;

    getmaxyx(stdscr, my, mx);
    s->win = newwin(my, mx, 0, 0);
}

void screen_free(screen *s)
{
    delwin(s->win);
    free(s);
}

void screen_refresh(screen *s)
{
    touchwin(s->win);
    wrefresh(s->win);
}

container *create_container()
{
    container *c = malloc(sizeof(container));

    c->focus = false;
    c->win = NULL;
    return c;
}

void free_container(container *c)
{
    if (c->win) delwin(c->win);
    free(c);
}

void screen_cache_insert(enum screen_type st, screen *s)
{
    screen_cache[st] = s;
}

void screen_cache_remove(enum screen_type st)
{
    if (screen_cache[st]) {
        SCREEN_FREE(screen_cache[st]);
        screen_cache[st] = NULL;
    }
}

void screen_cache_clear()
{
    for (int i = 0; i < NUM_SCREENS; i++) {
        if (screen_cache[i]) {
            SCREEN_FREE(screen_cache[i]);
            screen_cache[i] = NULL;
        }
    }
}

void print_packet(struct packet *p)
{
    char buf[MAXLINE];

    write_to_buf(buf, MAXLINE, p);
    main_screen_render((main_screen *) screen_cache[MAIN_SCREEN], buf);
}

void print_file()
{
    int my = getmaxy(screen_cache[MAIN_SCREEN]->win);

    for (int i = 0; i < vector_size(packets) && i < my; i++) {
        print_packet(vector_get_data(packets, i));
    }
    main_screen_set_interactive((main_screen *) screen_cache[MAIN_SCREEN], true);
}

void pop_screen()
{
    screen *oldscr = stack_pop(screen_stack);

    oldscr->focus = false;
    if (!stack_empty(screen_stack)) {
        screen *newscr = stack_top(screen_stack);

        newscr->focus = true;
        publish(screen_changed_publisher);
        wgetch(newscr->win); /* remove character from input queue */
        SCREEN_REFRESH(newscr);
    }
}

void push_screen(screen *newscr)
{
    screen *oldscr = stack_top(screen_stack);

    if (oldscr) {
        oldscr->focus = false;
    }
    newscr->focus = true;
    stack_push(screen_stack, newscr);
    publish(screen_changed_publisher);
    SCREEN_REFRESH(newscr);
}

inline bool screen_stack_empty()
{
    return stack_empty(screen_stack);
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
    if (scrollx < len) {
        mvwprintw(win, y, x, "%s", str + scrollx);
    }
}

void handle_input()
{
    screen *s = stack_top(screen_stack);

    if (s->op->screen_get_input) {
        SCREEN_GET_INPUT(s);
    }
}

void layout(enum event ev)
{
    switch (ev) {
    case NEW_PACKET:
        print_packet(vector_back(packets));
        break;
    case ALARM:
        stat_screen_print();
        break;
    default:
        break;
    }
}

void init_colours()
{
    /* colours on default background */
    for (int i = 0; i < NUM_COLOURS; i++) {
        init_pair(i + 1, i, -1);
    }
    for (int i = 0; i < NUM_COLOURS; i++) {
        for (int j = 0; j < NUM_COLOURS; j++) {
            init_pair(j + 1 + ((i + 1) * NUM_COLOURS), i, j);
        }
    }
    theme = DEFAULT;
}

inline int get_theme_colour(enum elements elem)
{
    return themes[theme][elem];
}

screen *help_screen_create()
{
    screen *s;
    static screen_operations op;

    op = SCREEN_OPTS(.screen_get_input = help_screen_get_input);
    s = screen_create(&op);
    return s;
}

void help_screen_get_input(screen *s)
{
    pop_screen(s);
}

void help_screen_render()
{
    int y = 0;
    WINDOW *win = screen_cache_get(HELP_SCREEN)->win;
    int hdrcol = get_theme_colour(HEADER_TXT);
    int subcol = get_theme_colour(SUBHEADER_TXT);

    wprintw(win, "Monitor 0.0.1 (c) 2017 John Olav Lund");
    mvwprintw(win, ++y, 0, "");
    mvwprintw(win, ++y, 0, "When a packet scan is active you can enter interactive mode " \
              "by pressing \'i\'. In interactive mode the packet scan will continue in the " \
              "background.");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, COLOR_PAIR(hdrcol) | A_BOLD, "General keyboard shortcuts");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "F1");
    wprintw(win, ": Show help");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "F10 q");
    wprintw(win, ": Quit");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, COLOR_PAIR(hdrcol) | A_BOLD, "Main screen keyboard shortcuts");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "i");
    wprintw(win, ": Enter interactive mode");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "s");
    wprintw(win, ": Show statistics screen");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "F2");
    wprintw(win, ": Show menu");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "F3");
    wprintw(win, ": Start packet scan");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "F4");
    wprintw(win, ": Stop packet scan");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "F5");
    wprintw(win, ": Save file in pcap format");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "F6");
    wprintw(win, ": Load file in pcap format");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "F7");
    wprintw(win, ": Change between decoded view or hexdump");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, COLOR_PAIR(hdrcol) | A_BOLD, "Keyboard shortcuts in interactive mode");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "Arrows");
    wprintw(win, ": Scroll the packet list");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "Space pgdown");
    wprintw(win, ": Scroll page down");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "b pgup");
    wprintw(win, ": Scroll page up");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "Home End");
    wprintw(win, ": Go to first/last page");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "g");
    wprintw(win, ": Go to line");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "h");
    wprintw(win, ": Change hexdump mode");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "Enter");
    wprintw(win, ": Inspect packet");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "Esc");
    wprintw(win, ": Close packet window/Quit interactive mode");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "i");
    wprintw(win, ": Quit interactive mode");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, COLOR_PAIR(hdrcol) | A_BOLD, "Statistics screen keyboard shortcuts");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "p");
    wprintw(win, ": Show/hide packet statistics");
    printat(win, ++y, 0, COLOR_PAIR(subcol) | A_BOLD, "%12s", "Esc x");
    wprintw(win, ": Exit statistics screen");
}
