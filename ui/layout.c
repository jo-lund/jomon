#include "layout.h"
#include "layout_int.h"
#include "protocols.h"
#include "main_screen.h"
#include "stat_screen.h"
#include "dialogue.h"
#include "../vector.h"
#include "../stack.h"
#include <string.h>

extern vector_t *packets;
publisher_t *screen_changed_publisher;
static screen *screen_cache[NUM_SCREENS];
static _stack_t *screen_stack;
static main_screen *ms;

void init_ncurses(bool capturing)
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
    set_escdelay(25); /* set escdelay to 25 ms */
    screen_changed_publisher = publisher_init();
    screen_stack = stack_init(NUM_SCREENS);
    memset(screen_cache, 0, NUM_SCREENS * sizeof(screen*));
    getmaxyx(stdscr, my, mx);
    ms = main_screen_create(my, mx, capturing);
}

void end_ncurses()
{
    main_screen_free(ms);
    for (int i = 0; i < NUM_SCREENS; i++) {
        if (screen_cache[i]) {
            free_screen(screen_cache[i]);
        }
    }
    publisher_free(screen_changed_publisher);
    endwin();
}

screen *create_screen(enum screen_type type)
{
    int mx, my;
    WINDOW *win;

    screen_cache[type] = malloc(sizeof(screen));
    getmaxyx(stdscr, my, mx);
    win = newwin(my, mx, 0, 0);
    screen_cache[type]->win = win;
    screen_cache[type]->type = type;
    screen_cache[type]->focus = false;
    return screen_cache[type];
}

screen *get_screen(enum screen_type type)
{
    if (screen_cache[type]) {
        return screen_cache[type];
    }
    return NULL;
}

void free_screen(screen *scr)
{
    if (scr) {
        delwin(scr->win);
        free(scr);
    }
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
    if (c) {
        if (c->win) delwin(c->win);
        free(c);
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
    int my = getmaxy(ms->pktlist);

    for (int i = 0; i < vector_size(packets) && i < my; i++) {
        print_packet(vector_get_data(packets, i));
    }
    main_screen_set_interactive(ms, true);
}

void pop_screen()
{
    screen *scr = stack_pop(screen_stack);

    scr->focus = false;
    if (stack_empty(screen_stack)) {
        wgetch(ms->pktlist); /* remove character from input queue */
        main_screen_refresh(ms);
    } else {
        screen *s = stack_top(screen_stack);

        s->focus = true;
        publish(screen_changed_publisher);
        wgetch(s->win); /* remove character from input queue */
        touchwin(s->win);
        wrefresh(s->win);
    }
}

void push_screen(screen *scr)
{
    screen *s = stack_top(screen_stack);

    if (s) s->focus = false;
    scr->focus = true;
    stack_push(screen_stack, scr);
    publish(screen_changed_publisher);
    touchwin(scr->win);
    wrefresh(scr->win);
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

    if (s) {
        switch (s->type) {
        case STAT_SCREEN:
            stat_screen_get_input();
            break;
        case HELP_SCREEN:
            pop_screen();
            break;
        case FILE_INPUT_DIALOGUE:
            FILE_INPUT_DIALOGUE_GET_INPUT((file_input_dialogue *) s);
            break;
        case LABEL_DIALOGUE:
            LABEL_DIALOGUE_GET_INPUT((label_dialogue *) s);
            break;
        default:
            break;
        }
    } else { /* main screen is not part of the screen stack */
        main_screen_get_input(ms);
    }
}

screen *help_screen_create()
{
    screen *scr;

    scr = create_screen(HELP_SCREEN);
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
