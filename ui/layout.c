#include "layout.h"
#include "layout_int.h"
#include "protocols.h"
#include "main_screen.h"
#include "stat_screen.h"
#include "dialogue.h"
#include "../vector.h"
#include "../stack.h"
#include "menu.h"
#include <string.h>

#define NUM_COLOURS 8

#define COLOUR_IDX(f, b) ((b == -1) ? (f) + 1 : (b) + 1 + ((f) + 1) * NUM_COLOURS)

extern vector_t *packets;
extern main_context ctx;
WINDOW *status;
main_menu *menu;
static struct screen *screen_cache[NUM_SCREENS];
static _stack_t *screen_stack;
static int theme;
static void init_colours();
static void change_theme(int i);

static int themes[NUM_THEMES][NUM_ELEMENTS] = {
    [DEFAULT] = {
        [HEADER]        = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [HEADER_TXT]    = COLOR_PAIR(COLOUR_IDX(COLOR_GREEN, -1)) | A_BOLD,
        [SUBHEADER_TXT] = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, -1)) | A_BOLD,
        [STATUS_BUTTON] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BUTTON]        = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [DIALOGUE_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)),
        [FD_LIST_BKGD]  = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, -1)),
        [FD_INPUT_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [FD_TEXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, -1)),
        [DISABLE]       = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, -1)) | A_BOLD,
        [FOCUS]         = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [SELECTIONBAR]  = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BACKGROUND]    = COLOR_PAIR(COLOUR_IDX(-1, -1))
    },
    [LIGHT] = {
        [HEADER]        = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_GREEN)),
        [HEADER_TXT]    = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)) | A_BOLD,
        [SUBHEADER_TXT] = COLOR_PAIR(COLOUR_IDX(COLOR_BLUE, COLOR_WHITE)),
        [STATUS_BUTTON] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BUTTON]        = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [DIALOGUE_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)),
        [FD_LIST_BKGD]  = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, COLOR_WHITE)),
        [FD_INPUT_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [FD_TEXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_BLUE, COLOR_WHITE)),
        [DISABLE]       = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_WHITE)) | A_BOLD,
        [FOCUS]         = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [SELECTIONBAR]  = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BACKGROUND]    = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE))
    },
    [DARK] = {
        [HEADER]        = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_MAGENTA)),
        [HEADER_TXT]    = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)) | A_BOLD,
        [SUBHEADER_TXT] = COLOR_PAIR(COLOUR_IDX(COLOR_BLUE, COLOR_BLACK)) | A_BOLD,
        [STATUS_BUTTON] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BUTTON]        = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [DIALOGUE_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLUE)),
        [FD_LIST_BKGD]  = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, COLOR_WHITE)),
        [FD_INPUT_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [FD_TEXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [DISABLE]       = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_BLACK)) | A_BOLD,
        [FOCUS]         = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [SELECTIONBAR]  = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BACKGROUND]    = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK))
    }
};

void init_ncurses()
{
    main_screen *ms;
    int mx, my;

    initscr(); /* initialize curses mode */
    cbreak(); /* disable line buffering */
    noecho();
    curs_set(0);
    use_default_colors();
    start_color();
    init_colours();
    set_escdelay(25); /* set escdelay to 25 ms */
    screen_stack = stack_init(NUM_SCREENS);
    getmaxyx(stdscr, my, mx);
    status = newwin(STATUS_HEIGHT, mx, my - STATUS_HEIGHT, 0);
    ms = main_screen_create();
    screen_cache_insert(MAIN_SCREEN, (screen *) ms);
    push_screen((screen *) ms);
    if (ctx.show_statistics) {
        screen *s = stat_screen_create();

        screen_cache_insert(STAT_SCREEN, s);
        push_screen(s);
    }
    menu = main_menu_create();
    menu->handler = change_theme;
}

void end_ncurses()
{
    screen_cache_clear();
    delwin(status);
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

screen *screen_cache_get(enum screen_type type)
{
    if (screen_cache[type]) {
        return screen_cache[type];
    }
    return NULL;
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
    main_screen_update((main_screen *) screen_cache[MAIN_SCREEN], buf);
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

void change_theme(int i)
{
    screen *s;
    screen *prev;

    /* refresh the top screen (menu) and the one behind */
    theme = i;
    s = stack_top(screen_stack);
    prev = stack_get(screen_stack, stack_size(screen_stack) - 2);
    SCREEN_REFRESH(prev);
    SCREEN_REFRESH(s);
}
