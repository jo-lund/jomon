#include <string.h>
#include <assert.h>
#include "layout.h"
#include "main_screen.h"
#include "stat_screen.h"
#include "help_screen.h"
#include "connection_screen.h"
#include "dialogue.h"
#include "menu.h"
#include "host_screen.h"
#include "screen.h"
#include "conversation_screen.h"
#include "actionbar.h"
#include "ui/ui.h"
#include "vector.h"
#include "stack.h"
#include "monitor.h"
#include "terminal.h"

#define NUM_COLOURS 8
#define COLOUR_IDX(f, b) ((b == -1) ? (f) + 1 : (b) + 1 + ((f) + 1) * NUM_COLOURS)

extern void main_screen_refresh(screen *s);
extern vector_t *packets;
main_menu *menu;
actionbar_t *actionbar;

static struct screen *screen_cache[NUM_SCREENS];
static _stack_t *screen_stack;
static int theme;
static void colours_init(void);
static void create_screens(void);
static void create_menu(void);
static void change_theme(int i);
static void options(int i);
static int screen_cache_type(screen *s);

static int themes[NUM_THEMES][NUM_ELEMENTS] = {
    [DEFAULT] = {
        [HEADER]        = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_GREEN)),
        [HEADER_TXT]    = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, -1)) | A_BOLD,
        [SUBHEADER_TXT] = COLOR_PAIR(COLOUR_IDX(COLOR_BLUE, -1)) | A_BOLD,
        [HELP_TXT]      = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, -1)),
        [STATUS_BUTTON] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BUTTON]        = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [DIALOGUE_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)),
        [FD_LIST_BKGD]  = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, -1)),
        [FD_INPUT_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [FD_TEXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, -1)),
        [DISABLE]       = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, -1)) | A_DIM,
        [FOCUS]         = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [SELECTIONBAR]  = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BACKGROUND]    = COLOR_PAIR(COLOUR_IDX(-1, -1)),
        [MENU_BACKGROUND] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_CYAN)),
        [MENU_SELECTIONBAR] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)),
        [SRC_TXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_MAGENTA, -1)) | A_BOLD,
        [DST_TXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_BLUE, -1)) | A_BOLD,
        [ERR_BKGD]      = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_RED)),
        [MARK]          = COLOR_PAIR(COLOUR_IDX(COLOR_YELLOW, -1)) | A_BOLD,
    },
    [LIGHT] = {
        [HEADER]        = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_GREEN)),
        [HEADER_TXT]    = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)) | A_BOLD,
        [SUBHEADER_TXT] = COLOR_PAIR(COLOUR_IDX(COLOR_BLUE, COLOR_WHITE)),
        [HELP_TXT]      = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, COLOR_WHITE)),
        [STATUS_BUTTON] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BUTTON]        = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [DIALOGUE_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)),
        [FD_LIST_BKGD]  = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, COLOR_WHITE)),
        [FD_INPUT_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [FD_TEXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_BLUE, COLOR_WHITE)),
        [DISABLE]       = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_WHITE)) | A_DIM,
        [FOCUS]         = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [SELECTIONBAR]  = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BACKGROUND]    = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [MENU_BACKGROUND] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)),
        [MENU_SELECTIONBAR] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [SRC_TXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_RED, COLOR_WHITE)),
        [DST_TXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_BLUE, COLOR_WHITE)) | A_BOLD,
        [ERR_BKGD]      = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_RED)),
        [MARK]          = COLOR_PAIR(COLOUR_IDX(COLOR_YELLOW, COLOR_WHITE)) | A_BOLD,
    },
    [DARK] = {
        [HEADER]        = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_MAGENTA)),
        [HEADER_TXT]    = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)) | A_BOLD,
        [SUBHEADER_TXT] = COLOR_PAIR(COLOUR_IDX(COLOR_BLUE, COLOR_BLACK)) | A_BOLD,
        [HELP_TXT]      = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, COLOR_BLACK)),
        [STATUS_BUTTON] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BUTTON]        = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [DIALOGUE_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLUE)),
        [FD_LIST_BKGD]  = COLOR_PAIR(COLOUR_IDX(COLOR_CYAN, COLOR_WHITE)),
        [FD_INPUT_BKGD] = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [FD_TEXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_WHITE)),
        [DISABLE]       = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)) | A_DIM,
        [FOCUS]         = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [SELECTIONBAR]  = COLOR_PAIR(COLOUR_IDX(COLOR_BLACK, COLOR_CYAN)),
        [BACKGROUND]    = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)),
        [MENU_BACKGROUND] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_CYAN)),
        [MENU_SELECTIONBAR] = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_BLACK)),
        [SRC_TXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_RED, COLOR_BLACK)),
        [DST_TXT]       = COLOR_PAIR(COLOUR_IDX(COLOR_BLUE, COLOR_BLACK)) | A_BOLD,
        [ERR_BKGD]      = COLOR_PAIR(COLOUR_IDX(COLOR_WHITE, COLOR_RED)),
        [MARK]          = COLOR_PAIR(COLOUR_IDX(COLOR_YELLOW, COLOR_BLACK)) | A_BOLD,
    }
};

static char *menu_themes[] = {
    "Default",
    "Light",
    "Dark"
};

static char *network_rate[] = {
    "Mibit/s",
    "Gibit/s",
    "kiB/s",
    "MiB/s",
    "GiB/s"
};

static char *name_resolution[] = {
    "Show TCP/UDP service names",
    "Use captured DNS data for reverse name resolution",
    "Reverse DNS lookups (Sends out DNS requests)"
};

static char *menu_options[] = {
    "Name resolution",
    "Network rate display"
};

static void ncurses_init(void);
static void ncurses_end(void);
static void ncurses_event(int);
static void print_file(void);

static struct ui ncurses_ui = {
    .name = "ncurses",
    .init = ncurses_init,
    .fini = ncurses_end,
    .draw = print_file,
    .event = ncurses_event
};

CONSTRUCTOR static void ncurses_register(void)
{
    ui_register(&ncurses_ui, true);
}

static void layout_resize(void)
{
    struct termsize size;
    screen *s;

    if (!get_termsize(&size))
        return;
    resizeterm(size.row, size.col);
    s = stack_top(screen_stack);
    s->resize = true;
    SCREEN_REFRESH(s);
    actionbar_refresh(actionbar, s);
    main_menu_resize(menu);
    s->resize = false;
}

static void ncurses_init(void)
{
    initscr(); /* initialize curses mode */
    cbreak(); /* disable line buffering */
    noecho();
    curs_set(0);
    colours_init();
    set_escdelay(25); /* set escdelay to 25 ms */
    screen_stack = stack_init(NUM_SCREENS);
    actionbar = actionbar_create();
    actionbar_add_default("F1", "Help", false);
    actionbar_add_default("F2", "Menu", false);
    actionbar_add_default("F3", "Back", false);
    actionbar_add_default("F10", "Quit", false);
    create_screens();
    create_menu();
}

static void ncurses_event(int event)
{
    screen *s;

    switch (event) {
    case UI_NEW_DATA:
        main_screen_update((main_screen *) screen_cache[MAIN_SCREEN],
                           vector_back(packets));
        break;
    case UI_RESIZE:
        layout_resize();
        break;
    case UI_INPUT:
        SCREEN_GET_INPUT((screen *) stack_top(screen_stack));
        break;
    case UI_ALARM:
        s = stack_top(screen_stack);
        switch (screen_cache_type(s)) {
        case STAT_SCREEN:
            stat_screen_print(s);
            break;
        case CONNECTION_SCREEN:
            SCREEN_REFRESH(s);
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
}

static void ncurses_end(void)
{
    screen_cache_clear();
    main_menu_free((screen *) menu);
    actionbar_free(actionbar);
    endwin();
}

container *create_container(void)
{
    container *c = xmalloc(sizeof(container));

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

void screen_cache_clear(void)
{
    for (int i = 0; i < NUM_SCREENS; i++) {
        if (screen_cache[i]) {
            SCREEN_FREE(screen_cache[i]);
            screen_cache[i] = NULL;
        }
    }
}

static int screen_cache_type(screen *s)
{
    for (int i = 0; i < NUM_SCREENS; i++) {
        if (s == screen_cache[i])
            return i;
    }
    return -1;
}

static void print_file(void)
{
    main_screen *ms = (main_screen *) screen_cache[MAIN_SCREEN];

    ms->base.top = 0;
    ms->base.show_selectionbar = true;
    main_screen_refresh((screen *) ms);
}

void pop_screen(void)
{
    screen *oldscr = stack_pop(screen_stack);
    screen *newscr = stack_top(screen_stack);

    assert(newscr != NULL);
    oldscr->focus = false;
    if (oldscr->op->screen_lost_focus) {
        SCREEN_LOST_FOCUS(oldscr, newscr);
    }
    newscr->focus = true;
    if (newscr->refreshing)
        return;
    newscr->refreshing = true;
    if (newscr->op->screen_got_focus) {
        SCREEN_GOT_FOCUS(newscr, oldscr);
    }
    SCREEN_REFRESH(newscr);
    actionbar_refresh(actionbar, newscr);
    newscr->refreshing = false;
}

void push_screen(screen *newscr)
{
    screen *oldscr = stack_top(screen_stack);

    if (oldscr) {
        oldscr->focus = false;
        if (oldscr->op->screen_lost_focus) {
            SCREEN_LOST_FOCUS(oldscr, newscr);
        }
    }
    newscr->focus = true;
    newscr->refreshing = true;
    stack_push(screen_stack, newscr);
    if (newscr->op->screen_got_focus) {
        SCREEN_GOT_FOCUS(newscr, oldscr);
    }
    SCREEN_REFRESH(newscr);
    actionbar_refresh(actionbar, newscr);
    newscr->refreshing = false;
}

bool screen_stack_empty(void)
{
    return stack_empty(screen_stack);
}

unsigned int screen_stack_size(void)
{
    return stack_size(screen_stack);
}

screen *screen_stack_top(void)
{
    return stack_top(screen_stack);
}

screen *screen_stack_prev(void)
{
    return stack_get(screen_stack, stack_size(screen_stack) - 2);
}

static int screen_stack_find(screen *s)
{
    unsigned int top = stack_size(screen_stack);
    unsigned int i = 0;

    while (i < top) {
        if (s == (screen *) stack_get(screen_stack, i)) {
            return i;
        }
        i++;
    }
    return -1;
}

void screen_stack_move_to_top(screen *s)
{
    int i = screen_stack_find(s);

    if (i > 0) {
        unsigned int top = stack_size(screen_stack) - 1;
        _stack_t *tmp;

        if (top == (unsigned) i) return; /* screen already on top of stack */
        tmp = stack_init(top - i);
        while (top-- > (unsigned) i) {
            stack_push(tmp, stack_pop(screen_stack));
        }
        stack_pop(screen_stack);
        while (!stack_empty(tmp)) {
            stack_push(screen_stack, stack_pop(tmp));
        }
        push_screen(s);
        stack_free(tmp, NULL);
    } else {
        push_screen(s);
    }
}

void printat(WINDOW *win, int attrs, const char *fmt, ...)
{
    char buf[MAXLINE];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, MAXLINE - 1, fmt, ap);
    va_end(ap);
    wattron(win, attrs);
    waddstr(win, buf);
    wattroff(win, attrs);
}

void mvprintat(WINDOW *win, int y, int x, int attrs, const char *fmt, ...)
{
    char buf[MAXLINE];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, MAXLINE - 1, fmt, ap);
    va_end(ap);
    wattron(win, attrs);
    mvwprintw(win, y, x, "%s", buf);
    wattroff(win, attrs);
}

void mvprintnlw(WINDOW *win, int y, int x, int scrollx, const char *fmt, ...)
{
    char buf[MAXLINE];
    va_list ap;
    int mx, len;

    mx = getmaxx(win);
    va_start(ap, fmt);
    vsnprintf(buf, MAXLINE - 1, fmt, ap);
    va_end(ap);
    len = strlen(buf);
    if (mx + scrollx - 1 < len + x && mx + scrollx - 1 - x > 0)
        buf[mx + scrollx - 1 - x] = '\0';
    if (scrollx < len)
        mvwprintw(win, y, x, "%s", buf + scrollx);
}

void mvputsnlw(WINDOW *win, int y, int x, int scrollx, char *str)
{
    int mx = getmaxx(win);
    int len = strlen(str);

    if (mx + scrollx - 1 < len + x && mx + scrollx - 1 - x > 0)
        str[mx + scrollx - 1 - x] = '\0';
    if (scrollx < len)
        mvwprintw(win, y, x, "%s", str + scrollx);
}

void colours_init(void)
{
    use_default_colors();
    start_color();
    for (int i = 0; i < NUM_COLOURS; i++) {
        init_pair(i + 1, i, -1); /* colours on default background */
        for (int j = 0; j < NUM_COLOURS; j++) {
            init_pair(j + 1 + ((i + 1) * NUM_COLOURS), i, j);
        }
    }
    theme = DEFAULT;
}

int get_theme_colour(enum elements elem)
{
    return themes[theme][elem];
}

void create_screens(void)
{
    main_screen *ms;
    screen *s;

    ms = main_screen_create();
    screen_cache_insert(MAIN_SCREEN, (screen *) ms);
    push_screen((screen *) ms);
    s = stat_screen_create();
    screen_cache_insert(STAT_SCREEN, s);
    if (ctx.opt.show_statistics) {
        push_screen(s);
    }
    screen_cache_insert(HELP_SCREEN, (screen *) help_screen_create());
    screen_cache_insert(CONNECTION_SCREEN, (screen *) connection_screen_create());
    screen_cache_insert(HOST_SCREEN, (screen *) host_screen_create());
    screen_cache_insert(CONVERSATION_SCREEN, (screen *) conversation_screen_create());
}

void create_menu(void)
{
    option_menu *om;

    menu = main_menu_create();
    main_menu_add_options(menu, MENU_NORMAL, "Themes", menu_themes, ARRAY_SIZE(menu_themes), change_theme);
    om = main_menu_add_options(menu, MENU_NORMAL, "Options", menu_options, ARRAY_SIZE(menu_options), NULL);
    main_menu_add_suboptions(om, MENU_MULTI_SELECT, 0, name_resolution, ARRAY_SIZE(name_resolution), options);
    main_menu_add_suboptions(om, MENU_SINGLE_SELECT, 1, network_rate, ARRAY_SIZE(network_rate), options);
    menu->current = list_begin(menu->opt);
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

void options(int i UNUSED)
{

}
