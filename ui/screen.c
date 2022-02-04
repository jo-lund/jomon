#include <stdlib.h>
#include "screen.h"
#include "layout.h"
#include "menu.h"
#include "../misc.h"

extern main_menu *menu;

static void handle_keydown(screen *s)
{
    if (!s->op->screen_get_data_size)
        return;
    if (s->show_selectionbar) {
        if ((unsigned int) s->selectionbar < SCREEN_GET_DATA_SIZE(s)) {
            s->selectionbar++;
            if (s->selectionbar - s->top == s->lines)
                s->top++;
            SCREEN_REFRESH(s);
        }
    } else {
        if ((unsigned int) s->top + s->lines < SCREEN_GET_DATA_SIZE(s)) {
            s->top++;
            SCREEN_REFRESH(s);
        }
    }
}

static void handle_keyup(screen *s)
{
    if (s->show_selectionbar) {
        if (s->top > 0 && s->selectionbar == s->top) {
            s->top--;
            s->selectionbar--;
        } else if (s->selectionbar > 0) {
            s->selectionbar--;
        }
    } else {
        if (s->top > 0) {
            s->top--;
        }
    }
    SCREEN_REFRESH(s);
}

static void scroll_page(screen *s, int num_lines)
{
    if (!s->op->screen_get_data_size)
        return;

    int i = abs(num_lines);
    int c = 0;

    if (num_lines > 0) { /* scroll down */
        while (c < i && (unsigned int) s->top + s->lines < SCREEN_GET_DATA_SIZE(s)) {
            s->top++;
            c++;
        }
        if (s->show_selectionbar)
            s->selectionbar += c;
    } else { /* scroll up */
        while (c < i && s->top > 0) {
            s->top--;
            c++;
        }
        if (s->show_selectionbar)
            s->selectionbar -= c;
    }
    if (c > 0)
        SCREEN_REFRESH(s);
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
    s->win = NULL;
    s->focus = false;
    s->have_selectionbar = false;
    s->selectionbar = 0;
    s->show_selectionbar = false;
    s->top = 0;
    s->page = 0;
    s->num_pages = 0;
    s->lines = getmaxy(stdscr);
    s->refreshing = false;
    s->fullscreen = true;
    s->resize = false;
}

void screen_free(screen *s)
{
    if (s->win)
        delwin(s->win);
    free(s);
}

void screen_refresh(screen *s)
{
    touchwin(s->win);
    wrefresh(s->win);
}

void screen_get_input(screen *s)
{
    int c = wgetch(s->win);
    int my = getmaxy(s->win);

    switch (c) {
    case 'c':
        screen_stack_move_to_top(screen_cache_get(CONNECTION_SCREEN));
        break;
    case 'h':
        screen_stack_move_to_top(screen_cache_get(HOST_SCREEN));
        break;
    case 'i':
        if (s->have_selectionbar && SCREEN_GET_DATA_SIZE(s) > 0) {
            s->show_selectionbar = !s->show_selectionbar;
            s->selectionbar = s->top;
            SCREEN_REFRESH(s);
        }
        break;
    case 'p':
        if (s->num_pages > 0) {
            s->page = (s->page + 1) % s->num_pages;
            SCREEN_REFRESH(s);
        }
        break;
    case 's':
        screen_stack_move_to_top(screen_cache_get(STAT_SCREEN));
        break;
    case 'x':
    case KEY_ESC:
    case KEY_F(3):
        if (screen_stack_size() > 1) {
            if (s->op->screen_on_back)
                SCREEN_ON_BACK(s);
            pop_screen();
        }
        break;
    case KEY_F(1):
        screen_stack_move_to_top(screen_cache_get(HELP_SCREEN));
        break;
    case KEY_F(2):
        push_screen((screen *) menu);
        break;
    case KEY_F(10):
    case 'q':
        finish(0);
        break;
    case KEY_UP:
        handle_keyup(s);
        break;
    case KEY_DOWN:
        handle_keydown(s);
        break;
    case ' ':
    case KEY_NPAGE:
        scroll_page(s, my);
        break;
    case 'b':
    case KEY_PPAGE:
        scroll_page(s, -my);
        break;
    case KEY_HOME:
        if (s->show_selectionbar)
            s->selectionbar = 0;
        s->top = 0;
        SCREEN_REFRESH(s);
        break;
    case KEY_END:
        break;
    default:
        break;
    }
}
