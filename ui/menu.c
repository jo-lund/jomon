#include "menu.h"
#include <stdlib.h>

extern WINDOW *status;

struct menu_options {
    char *header;
    char **opt;
    int num_opts;
};

static char *themes[] = { "Default", "Light", "Dark" };

static struct menu_options options[] = {
    { "Themes", themes, 3 },
    { "Options", NULL, 0 }
};

#define NUM_HEADERS (sizeof(options) / sizeof(struct menu_options))

static void main_menu_init(screen *s);
static void main_menu_get_input(screen *s);
static void main_menu_refresh(screen *s);

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
    menu->base.win = newwin(5, 12, my - 6, 0);
    menu->opt = derwin(menu->base.win, 3, 10, 1, 1);
    menu->header = newwin(1, mx, my - 1, 0);
    box(menu->base.win, 0, 0);
    nodelay(menu->base.win, TRUE);
    keypad(menu->base.win, TRUE);
    main_menu_init((screen *) menu);
    return menu;
}

void main_menu_init(screen *s)
{
    int y = 0;
    int x = 1;
    main_menu *menu = (main_menu *) s;

    menu->i = 0;
    for (unsigned int i = 0; i < NUM_HEADERS; i++) {
        for (int j = 0; j < options[i].num_opts; j++) {
            mvwprintw(menu->opt, y++, 1, options[i].opt[j]);
        }
        printat(menu->header, 0, x + 12 * i, A_NORMAL, options[i].header);
    }
}

void main_menu_refresh(screen *s)
{
    main_menu *menu = (main_menu *) s;

    wbkgd(menu->base.win, get_theme_colour(BACKGROUND));
    wbkgd(menu->opt, get_theme_colour(BACKGROUND));
    wbkgd(menu->header, get_theme_colour(BACKGROUND));
    show_selectionbar(menu->opt, menu->i);
    werase(status);
    touchwin(status);
    touchwin(s->win);
    touchwin(menu->opt);
    touchwin(menu->header);
    wnoutrefresh(status);
    wnoutrefresh(s->win);
    wnoutrefresh(menu->opt);
    wnoutrefresh(menu->header);
    doupdate();
}

void main_menu_free(screen *s)
{
    main_menu *menu = (main_menu *) s;

    delwin(s->win);
    delwin(menu->opt);
    delwin(menu->header);
    free(menu);
}

void main_menu_get_input(screen *s)
{
    int c;
    main_menu *menu = (main_menu *) s;

    c = wgetch(s->win);
    switch (c) {
    case KEY_ESC:
    case KEY_F(2):
    case KEY_F(10):
    case 'q':
        pop_screen(s);
        break;
    case KEY_DOWN:
        remove_selectionbar(menu->opt, menu->i);
        menu->i = (menu->i + 1) % NUM_THEMES;
        show_selectionbar(menu->opt, menu->i);
        wrefresh(menu->opt);
        break;
    case KEY_UP:
        remove_selectionbar(menu->opt, menu->i);
        menu->i = (menu->i == 0) ? (NUM_THEMES - 1) : (menu->i - 1) % NUM_THEMES;
        show_selectionbar(menu->opt, menu->i);
        wrefresh(menu->opt);
        break;
    case KEY_ENTER:
    case '\n':
        menu->handler(menu->i);
        break;
    default:
        break;
    }
}
