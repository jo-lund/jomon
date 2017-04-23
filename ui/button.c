#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include "button.h"

static void button_set_action(button *b, button_action act);
static void button_render(button *b);

button *button_create(screen *scr, button_action act, char *txt, int y, int x)
{
    button *b = malloc(sizeof(button));

    b->c.win = derwin(scr->win, 3, 12, y, x);
    b->txt = txt;
    b->action = act;
    b->button_render = button_render;
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
    mvwprintw(win, my / 2, (mx - len) / 2, b->txt);
    wbkgd(win, COLOR_PAIR(1));
    wrefresh(win);
}
