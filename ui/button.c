#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include "button.h"

static void button_set_action(button *b, button_action act);
static void button_render(button *b);
static void button_set_focus(button *b, bool has_focus);

button *button_create(screen *scr, button_action act, char *txt, int y, int x)
{
    button *b = malloc(sizeof(button));

    b->c.win = derwin(scr->win, 3, 12, y, x);
    b->c.focus = false;
    b->txt = txt;
    b->action = act;
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

void button_set_action(button *b, button_action act)
{
    b->action = act;
}

void button_render(button *b)
{
    int len;
    int my, mx;
    WINDOW *win;

    win = ((container *) b)->win;
    len = strlen(b->txt);
    getmaxyx(win, my, mx);
    if (((container *) b)->focus) {
        box(win, 0, 0);
    } else {
        werase(win);
    }
    mvwprintw(win, my / 2, (mx - len) / 2, b->txt);
    wbkgd(win, COLOR_PAIR(1));
    wrefresh(win);
}

void button_set_focus(button *b, bool has_focus)
{
    ((container *) b)->focus = has_focus;
}
