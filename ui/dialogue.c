#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <ctype.h>
#include "dialogue.h"
#include "../misc.h"

static char file[MAXLINE];
static int num_chars;

static void dialogue_set_title(dialogue *d, char *title);
static void dialogue_render(dialogue *d);
static void input_dialogue_get_input(input_dialogue *id);
static void input_dialogue_render(input_dialogue *id);
static void input_dialogue_set_button_action(input_dialogue *id, button_action ok,
                                             button_action cancel);
static void input_dialogue_handle_enter(input_dialogue *id);

dialogue *dialogue_create(char *title)
{
    dialogue *d = malloc(sizeof(dialogue));
    int my, mx;

    getmaxyx(stdscr, my, mx);
    d->height  = my / 5;
    d->width = mx / 5;
    d->scr.focus = false;
    d->scr.type = DIALOGUE;
    d->scr.win = newwin(d->height, d->width, (my - d->height) / 2, (mx - d->width) / 2);
    d->title = title;
    d->dialogue_set_title = dialogue_set_title;
    d->dialogue_render = dialogue_render;
    return d;
}

void dialogue_free(dialogue *d)
{
    if (d) {
        delwin(d->scr.win);
        free(d);
    }
}

void dialogue_set_title(dialogue *d, char *title)
{
    if (d) {
        d->title = title;
    }
}

void dialogue_render(dialogue *d)
{
    int mx;
    WINDOW *win;
    int len;

    win = ((screen *) d)->win;
    mx = getmaxx(win);
    box(d->scr.win, 0, 0);
    wbkgd(win, COLOR_PAIR(5));
    if (d->title) {
        len = strlen(d->title);
        mvwprintw(win, 0, (mx - len) / 2, d->title);
        printat(win, 0, (mx - len) / 2, A_BOLD, d->title);
    }
    wrefresh(win);
}

input_dialogue *input_dialogue_create(char *title, char *input_txt, button_action ok, button_action cancel)
{
    input_dialogue *id = malloc(sizeof(input_dialogue));
    int my, mx;
    dialogue *d;

    d = dialogue_create(title);
    memcpy(id->d, d, sizeof(dialogue));
    getmaxyx(d->scr.win, my, mx);
    id->ok = button_create((screen *) d, ok, "Ok", my - 5, 4);
    id->cancel = button_create((screen *) d, cancel, "Cancel", my - 5, mx - 16);
    id->input.win = derwin(((screen *) d)->win, 1, mx - 8, 6, 4);
    id->input.focus = false;
    id->has_focus = 0;
    id->input_txt = input_txt;
    id->input_dialogue_set_button_action = input_dialogue_set_button_action;
    id->input_dialogue_get_input = input_dialogue_get_input;
    id->input_dialogue_render = input_dialogue_render;
    nodelay(id->input.win, TRUE);
    keypad(id->input.win, TRUE);
    num_chars = 0;
    return id;
}

void input_dialogue_free(input_dialogue *id)
{
    if (id) {
        button_free(id->ok);
        button_free(id->cancel);
        delwin(id->input.win);
        dialogue_free((dialogue *) id);
        free(id);
    }
}

void input_dialogue_set_input(input_dialogue *id, char *input)
{
    if (id) {
        id->input_txt = input;
    }
}

void input_dialogue_set_button_action(input_dialogue *id, button_action ok, button_action cancel)
{
    BUTTON_SET_ACTION(id->ok, ok);
    BUTTON_SET_ACTION(id->cancel, cancel);
}

void input_dialogue_get_input(input_dialogue *id)
{
    int c;

    c = wgetch(id->input.win);
    switch (c) {
    case '\t':
        id->has_focus = (id->has_focus + 1) % 3;
        input_dialogue_render(id);
        break;
    case KEY_ENTER:
    case '\n':
        input_dialogue_handle_enter(id);
        break;
    case KEY_ESC:
        curs_set(0);
        pop_screen();
        break;
    case '\b':
    case KEY_BACKSPACE:
    {
        int y, x;

        getyx(id->input.win, y, x);
        if (x > 0) {
            if (num_chars > 0) --num_chars;
            mvwdelch(id->input.win, y, x - 1);
            wrefresh(id->input.win);
        }
        break;
    }
    default:
        if (isprint(c)) {
            file[num_chars++] = (char) c;
            waddch(id->input.win, c);
            wrefresh(id->input.win);
        }
        break;
    }
}

void input_dialogue_render(input_dialogue *id)
{
    werase(((container *) id->ok)->win);
    werase(((container *) id->cancel)->win);
    DIALOGUE_RENDER((dialogue *) id);
    BUTTON_RENDER(id->ok);
    BUTTON_RENDER(id->cancel);
    mvwprintw(((screen *) id)->win, 5, 4, "%s: ", id->input_txt);
    wbkgd(id->input.win, COLOR_PAIR(1));

    switch (id->has_focus) {
    case 0:
        wmove(((screen *) id)->win, 6, 4);
        curs_set(1);
        break;
    case 1:
        curs_set(0);
        box(((container *) id->ok)->win, 0, 0);
        wrefresh(((container *) id->ok)->win);
        break;
    case 2:
        box(((container *) id->cancel)->win, 0, 0);
        wrefresh(((container *) id->cancel)->win);
        break;
    }
    wrefresh(id->input.win);
    wrefresh(((screen *) id)->win);
}

void input_dialogue_handle_enter(input_dialogue *id)
{
    switch (id->has_focus) {
    case 0:
    case 1:
    {
        if (num_chars) {
            file[num_chars] = '\0';
            curs_set(0);
            id->ok->action(file);
        }
        break;
    }
    case 2:
        curs_set(0);
        id->cancel->action(NULL);
        break;
    }
}
