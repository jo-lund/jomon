#include "menu.h"
#include "layout_int.h"
#include <stdlib.h>

extern WINDOW *status;

typedef struct menu_options {
    char *header;
    char **opts;
    int num_opts;
} menu_options;

typedef struct option_menu {
    menu_options options;
    WINDOW *frame;
    WINDOW *content; // Can be made into a list when we have several subwindows
    int i;
    menu_handler handler;
} option_menu;

static void main_menu_get_input(screen *s);
static void main_menu_refresh(screen *s);
static void main_menu_print(screen *s);
static void handle_new_focus(screen *s, int c);

static void show_selectionbar(WINDOW *win, int line)
{
    mvwchgat(win, line, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(SELECTIONBAR)), NULL);
}

static void remove_selectionbar(WINDOW *win, int line)
{
    mvwchgat(win, line, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(BACKGROUND)), NULL);
}

main_menu *main_menu_create()
{
    static screen_operations op;
    main_menu *menu;
    int my, mx;

    getmaxyx(stdscr, my, mx);
    op = SCREEN_OPS(.screen_free = main_menu_free,
                    .screen_refresh = main_menu_refresh,
                    .screen_get_input = main_menu_get_input);

    menu = malloc(sizeof(main_menu));
    menu->base.op = &op;
    menu->base.win = newwin(1, mx, my - 1, 0);
    menu->base.focus = false;
    menu->update = true;
    menu->opt = list_init();
    return menu;
}

void main_menu_add_options(main_menu *menu, char *header, char **opts, int num_opts,
                           menu_handler fn, int rows, int cols, int begy, int begx)
{
    option_menu *om;

    om = calloc(1, sizeof(option_menu));
    om->frame = newwin(rows, cols, begy, begx);
    om->content = derwin(om->frame, rows - 2, cols - 2, 1, 1);
    om->options.header = header;
    om->options.opts = opts;
    om->options.num_opts = num_opts;
    om->handler = fn;
    box(om->frame, 0, 0);
    nodelay(om->frame, TRUE);
    keypad(om->frame, TRUE);
    list_push_back(menu->opt, om);
}

void main_menu_print(screen *s)
{
    int y = 0;
    int x = 1;
    main_menu *menu = (main_menu *) s;
    const node_t *n = list_begin(menu->opt);
    int i = 0;

    while (n) {
        option_menu *focused = list_data(n);

        focused->i = 0;
        for (int j = 0; j < focused->options.num_opts; j++) {
            mvwprintw(focused->content, y++, 1, focused->options.opts[j]);
        }
        printat(menu->base.win, 0, x + 12 * i, A_NORMAL, focused->options.header);
        y = 0;
        i++;
        n = list_next(n);
    }
}

void main_menu_refresh(screen *s)
{
    main_menu *menu = (main_menu *) s;
    option_menu *focused = list_data(menu->cur);
    screen *prev = screen_stack_prev();

    wbkgd(menu->base.win, get_theme_colour(BACKGROUND));
    wbkgd(focused->frame, get_theme_colour(BACKGROUND));
    wbkgd(focused->content, get_theme_colour(BACKGROUND));
    if (menu->update) {
        main_menu_print(s);
        menu->update = false;
    }
    SCREEN_REFRESH(prev);
    show_selectionbar(focused->content, focused->i);
    werase(status);
    touchwin(status);
    touchwin(menu->base.win);
    touchwin(focused->frame);
    touchwin(focused->content);
    wnoutrefresh(status);
    wnoutrefresh(menu->base.win);
    wnoutrefresh(focused->frame);
    wnoutrefresh(focused->content);
    doupdate();
}

void main_menu_free(screen *s)
{
    main_menu *menu = (main_menu *) s;
    option_menu *focused = list_data(menu->cur);

    delwin(menu->base.win);
    delwin(focused->frame);
    delwin(focused->content);
    free(focused);
    free(menu);
}

void main_menu_get_input(screen *s)
{
    int c;
    main_menu *menu = (main_menu *) s;
    option_menu *focused = list_data(menu->cur);

    c = wgetch(focused->frame);
    switch (c) {
    case KEY_ESC:
    case KEY_F(2):
    case KEY_F(10):
    case 'q':
        pop_screen(s);
        break;
    case KEY_DOWN:
        remove_selectionbar(focused->content, focused->i);
        focused->i = (focused->i + 1) % focused->options.num_opts;
        show_selectionbar(focused->content, focused->i);
        wrefresh(focused->content);
        break;
    case KEY_UP:
        remove_selectionbar(focused->content, focused->i);
        focused->i = (focused->i == 0) ? (focused->options.num_opts - 1) :
            (focused->i - 1) % focused->options.num_opts;
        show_selectionbar(focused->content, focused->i);
        wrefresh(focused->content);
        break;
    case KEY_RIGHT:
    case KEY_LEFT:
        handle_new_focus(s, c);
        break;
    case KEY_ENTER:
    case '\n':
        focused->handler(focused->i);
        break;
    default:
        break;
    }
}

void handle_new_focus(screen *s, int c)
{
    main_menu *menu = (main_menu *) s;
    const node_t *n = (c == KEY_RIGHT) ? list_next(menu->cur) :
        list_prev(menu->cur);

    if (n) {
        menu->cur = n;
        main_menu_refresh(s);
    }
}
