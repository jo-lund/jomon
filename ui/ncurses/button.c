#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include "button.h"
#include "screen.h"

static void button_set_action(button *b, button_action act, void *arg);
static void button_render(button *b);
static void button_set_focus(button *b, bool has_focus);

button *button_create(screen *scr, button_action act, void *arg, char *txt, int y, int x)
{
    button *b = malloc(sizeof(button));

    b->c.win = derwin(scr->win, 1, 12, y, x);
    b->c.focus = false;
    b->txt = txt;
    b->action = act;
    b->argument = arg;
    b->button_render = button_render;
    b->button_set_action = button_set_action;
    b->button_set_focus = button_set_focus;
    return b;
}

void button_free(button *b)
{
    delwin(b->c.win);
    free(b);
}

void button_set_action(button *b, button_action act, void *arg)
{
    b->action = act;
    b->argument = arg;
}

void button_render(button *b)
{
    int len;
    int my, mx;
    WINDOW *win;

    win = ((container *) b)->win;
    len = strlen(b->txt) + 4;
    getmaxyx(win, my, mx);
    if (((container *) b)->focus) {
        wbkgd(win, get_theme_colour(FOCUS));
    } else {
        wbkgd(win, get_theme_colour(BUTTON));
    }
    mvwprintw(win, my / 2, (mx - len) / 2, "[ %s ]", b->txt);
    wrefresh(win);
}

void button_set_focus(button *b, bool has_focus)
{
    ((container *) b)->focus = has_focus;
}
