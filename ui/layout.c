#include "layout.h"
#include "layout_int.h"
#include "protocols.h"
#include "main_screen.h"
#include "stat_screen.h"
#include "dialogue.h"
#include "../vector.h"
#include "../stack.h"
#include <string.h>

struct screen_cache_item {
    screen *scr;
    free_screen_fn fn;
};

static void screen_cache_insert(enum screen_type type, screen *s, free_screen_fn fn);
static void screen_cache_clear();
static void screen_refresh(screen *s);

extern vector_t *packets;
extern main_context ctx;
publisher_t *screen_changed_publisher;
static struct screen_cache_item screen_cache[NUM_SCREENS];
static _stack_t *screen_stack;
static main_screen *ms;

void init_ncurses(main_context *ctx)
{
    int mx, my;

    initscr(); /* initialize curses mode */
    cbreak(); /* disable line buffering */
    noecho();
    curs_set(0);
    use_default_colors();
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_CYAN);
    init_pair(2, COLOR_BLACK, COLOR_CYAN);
    init_pair(3, COLOR_CYAN, -1);
    init_pair(4, COLOR_GREEN, -1);
    init_pair(5, COLOR_BLUE, -1);
    init_pair(6, COLOR_YELLOW, -1);
    init_pair(7, COLOR_MAGENTA, -1);
    init_pair(8, COLOR_RED, -1);
    init_pair(9, COLOR_WHITE, COLOR_BLUE);
    init_pair(10, COLOR_BLACK, -1);
    init_pair(11, COLOR_WHITE, COLOR_BLACK);
    init_pair(12, COLOR_BLACK, COLOR_WHITE);
    set_escdelay(25); /* set escdelay to 25 ms */
    screen_changed_publisher = publisher_init();
    screen_stack = stack_init(NUM_SCREENS);
    getmaxyx(stdscr, my, mx);
    ms = main_screen_create(my, mx, ctx);
    screen_cache_insert(MAIN_SCREEN, (screen *) ms, main_screen_free);
    push_screen((screen *) ms);
}

void end_ncurses()
{
    screen_cache_clear();
    publisher_free(screen_changed_publisher);
    endwin();
}

screen *create_screen(enum screen_type type, free_screen_fn fn)
{
    if (!screen_cache[type].scr) {
        int mx, my;

        screen_cache[type].scr = malloc(sizeof(screen));
        getmaxyx(stdscr, my, mx);
        screen_cache[type].scr->win = newwin(my, mx, 0, 0);
        screen_cache[type].scr->type = type;
        screen_cache[type].scr->focus = false;
        screen_cache[type].scr->screen_refresh = screen_refresh;
        if (fn) {
            screen_cache[type].fn = fn;
        } else {
            screen_cache[type].fn = free_screen;
        }
    }
    return screen_cache[type].scr;
}

screen *get_screen(enum screen_type type)
{
    if (screen_cache[type].scr) {
        return screen_cache[type].scr;
    }
    return NULL;
}

void free_screen(void *s)
{
    screen *scr = (screen *) s;

    if (scr->win) delwin(scr->win);
    free(scr);
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

void screen_cache_insert(enum screen_type type, screen *s, free_screen_fn fn)
{
    screen_cache[type].scr = s;
    screen_cache[type].fn = fn;
}

void screen_cache_clear()
{
    for (int i = 0; i < NUM_SCREENS; i++) {
        if (screen_cache[i].scr) {
            screen_cache[i].fn(screen_cache[i].scr);
            screen_cache[i].scr = NULL;
            screen_cache[i].fn = NULL;
        }
    }
}

void print_packet(struct packet *p)
{
    char buf[MAXLINE];

    write_to_buf(buf, MAXLINE, p);
    main_screen_render(ms, buf);
}

void print_file()
{
    int my = getmaxy(ms->base.win);

    for (int i = 0; i < vector_size(packets) && i < my; i++) {
        print_packet(vector_get_data(packets, i));
    }
    main_screen_set_interactive(ms, true);
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

    // TODO: get_input should be part of struct screen
    if (s) {
        switch (s->type) {
        case MAIN_SCREEN:
            main_screen_get_input(ms);
            break;
        case STAT_SCREEN:
            stat_screen_get_input();
            break;
        case HELP_SCREEN:
            pop_screen();
            break;
        case LABEL_DIALOGUE:
            LABEL_DIALOGUE_GET_INPUT((label_dialogue *) s);
            break;
        case FILE_DIALOGUE:
            FILE_DIALOGUE_GET_INPUT((file_dialogue *) s);
            break;
        default:
            break;
        }
    }
}

void layout(enum event ev)
{
    screen *s;

    switch (ev) {
    case NEW_PACKET:
        print_packet(vector_back(packets));
        break;
    case ALARM:
        s = stack_top(screen_stack);
        if (s && s->type == STAT_SCREEN) {
            stat_screen_print();
        }
        break;
    default:
        break;
    }
}

screen *help_screen_create()
{
    screen *scr;

    scr = create_screen(HELP_SCREEN, NULL);
    help_screen_render();
    return scr;
}

void help_screen_render()
{
    int y = 0;
    WINDOW *win = get_screen(HELP_SCREEN)->win;

    wprintw(win, "Monitor 0.0.1 (c) 2017 John Olav Lund");
    mvwprintw(win, ++y, 0, "");
    mvwprintw(win, ++y, 0, "When a packet scan is active you can enter interactive mode " \
              "by pressing \'i\'. In interactive mode the packet scan will continue in the " \
              "background.");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, GREEN | A_BOLD, "General keyboard shortcuts");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "F1");
    wprintw(win, ": Show help");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "F10 q");
    wprintw(win, ": Quit");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, GREEN | A_BOLD, "Main screen keyboard shortcuts");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "i");
    wprintw(win, ": Enter interactive mode");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "s");
    wprintw(win, ": Show statistics screen");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "F2");
    wprintw(win, ": Show menu");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "F3");
    wprintw(win, ": Start packet scan");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "F4");
    wprintw(win, ": Stop packet scan");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "F5");
    wprintw(win, ": Save file in pcap format");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "F6");
    wprintw(win, ": Load file in pcap format");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "F7");
    wprintw(win, ": Change between decoded view or hexdump");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, GREEN | A_BOLD, "Keyboard shortcuts in interactive mode");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "Arrows");
    wprintw(win, ": Scroll the packet list");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "Space pgdown");
    wprintw(win, ": Scroll page down");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "b pgup");
    wprintw(win, ": Scroll page up");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "Home End");
    wprintw(win, ": Go to first/last page");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "g");
    wprintw(win, ": Go to line");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "h");
    wprintw(win, ": Change hexdump mode");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "Enter");
    wprintw(win, ": Inspect packet");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "Esc");
    wprintw(win, ": Close packet window/Quit interactive mode");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "i");
    wprintw(win, ": Quit interactive mode");
    mvwprintw(win, ++y, 0, "");
    printat(win, ++y, 0, GREEN | A_BOLD, "Statistics screen keyboard shortcuts");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "p");
    wprintw(win, ": Show/hide packet statistics");
    printat(win, ++y, 0, CYAN | A_BOLD, "%12s", "Esc x");
    wprintw(win, ": Exit statistics screen");
}
