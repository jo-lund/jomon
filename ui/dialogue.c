#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <ctype.h>
#include <unistd.h>
#include "dialogue.h"
#include "../misc.h"

static char file[MAXPATH + 1];
static int num_chars;

static void dialogue_set_title(dialogue *d, char *title);
static void dialogue_render(dialogue *d);
static void file_input_dialogue_get_input(file_input_dialogue *id);
static void file_input_dialogue_set_input(file_input_dialogue *id, char *input);
static void file_input_dialogue_render(file_input_dialogue *id);
static void file_input_dialogue_set_button_action(file_input_dialogue *id, button_action ok,
                                             button_action cancel);
static void file_input_dialogue_handle_enter(file_input_dialogue *id);
static void label_dialogue_render(label_dialogue *ld);
static void label_dialogue_get_input(struct label_dialogue *ld);

dialogue *dialogue_create(char *title)
{
    dialogue *d = malloc(sizeof(dialogue));
    int my, mx;

    getmaxyx(stdscr, my, mx);
    d->height  = my / 5;
    d->width = mx / 5 + 10;
    d->screen_base.focus = false;
    d->screen_base.win = newwin(d->height, d->width, (my - d->height) / 2, (mx - d->width) / 2);
    d->title = title;
    d->dialogue_set_title = dialogue_set_title;
    d->dialogue_render = dialogue_render;
    return d;
}

void dialogue_free(dialogue *d)
{
    if (d) {
        delwin(((screen *) d)->win);
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
    box(win, 0, 0);
    wbkgd(win, COLOR_PAIR(5));
    if (d->title) {
        len = strlen(d->title);
        mvwprintw(win, 0, (mx - len) / 2, d->title);
        printat(win, 0, (mx - len) / 2, A_BOLD, d->title);
    }
    wrefresh(win);
}

file_input_dialogue *file_input_dialogue_create(char *title, button_action ok, button_action cancel)
{
    file_input_dialogue *id;
    int my, mx;
    dialogue *d;

    id = malloc(sizeof(file_input_dialogue));
    d = dialogue_create(title);
    memcpy(id->dialogue_base, d, sizeof(dialogue));
    free(d);
    getmaxyx(((screen *) id)->win, my, mx);
    ((screen *) id)->type = FILE_INPUT_DIALOGUE;
    id->ok = button_create((screen *) id, ok, "Ok", my - 5, 4);
    id->cancel = button_create((screen *) id, cancel, "Cancel", my - 5, mx - 16);
    id->input.win = derwin(((screen *) id)->win, 1, mx - 8, 6, 4);
    id->input.focus = false;
    id->has_focus = 0;
    id->file_input_dialogue_set_button_action = file_input_dialogue_set_button_action;
    id->file_input_dialogue_get_input = file_input_dialogue_get_input;
    id->file_input_dialogue_set_input = file_input_dialogue_set_input;
    id->file_input_dialogue_render = file_input_dialogue_render;
    nodelay(id->input.win, TRUE);
    keypad(id->input.win, TRUE);
    getcwd(file, MAXPATH); // TODO: Use file path of loaded file if available
    waddstr(id->input.win, file);
    num_chars = strlen(file);
    file_input_dialogue_render(id);
    return id;
}

void file_input_dialogue_free(file_input_dialogue *id)
{
    if (id) {
        button_free(id->ok);
        button_free(id->cancel);
        delwin(id->input.win);
        delwin(((screen *) id)->win);
        free(id);
    }
}

void file_input_dialogue_set_input(file_input_dialogue *id, char *input)
{
    if (id) {
        strncpy(file, input, MAXPATH);
        werase(id->input.win);
        waddstr(id->input.win, file);
        num_chars = strlen(file);
        file_input_dialogue_render(id);
    }
}

void file_input_dialogue_set_button_action(file_input_dialogue *id, button_action ok, button_action cancel)
{
    BUTTON_SET_ACTION(id->ok, ok);
    BUTTON_SET_ACTION(id->cancel, cancel);
}

void file_input_dialogue_get_input(file_input_dialogue *id)
{
    int c;

    c = wgetch(id->input.win);
    switch (c) {
    case '\t':
        id->has_focus = (id->has_focus + 1) % 3;
        file_input_dialogue_render(id);
        break;
    case KEY_ENTER:
    case '\n':
        file_input_dialogue_handle_enter(id);
        break;
    case KEY_ESC:
        curs_set(0);
        pop_screen();
        id->cancel->action(NULL);
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

void file_input_dialogue_render(file_input_dialogue *id)
{
    werase(((container *) id->ok)->win);
    werase(((container *) id->cancel)->win);
    DIALOGUE_RENDER((dialogue *) id);
    mvwprintw(((screen *) id)->win, 5, 4, "File path: ");
    wbkgd(id->input.win, COLOR_PAIR(1));

    switch (id->has_focus) {
    case 0:
        wmove(((screen *) id)->win, 6, num_chars + 4);
        curs_set(1);
        BUTTON_SET_FOCUS(id->ok, false);
        BUTTON_SET_FOCUS(id->cancel, false);
        break;
    case 1:
        curs_set(0);
        BUTTON_SET_FOCUS(id->ok, true);
        break;
    case 2:
        BUTTON_SET_FOCUS(id->ok, false);
        BUTTON_SET_FOCUS(id->cancel, true);
        break;
    }
    BUTTON_RENDER(id->ok);
    BUTTON_RENDER(id->cancel);
    wrefresh(id->input.win);
    wrefresh(((screen *) id)->win);
}

void file_input_dialogue_handle_enter(file_input_dialogue *id)
{
    switch (id->has_focus) {
    case 0:
    case 1:
        if (num_chars) {
            file[num_chars] = '\0';
            curs_set(0);
            pop_screen();
            id->ok->action(file);
        }
        break;
    case 2:
        curs_set(0);
        pop_screen();
        id->cancel->action(NULL);
        break;
    }
}

label_dialogue *label_dialogue_create(char *title, char *label, button_action act)
{
    label_dialogue *ld;
    dialogue *d;

    ld = malloc(sizeof(label_dialogue));
    d = dialogue_create(title);
    memcpy(ld->dialogue_base, d, sizeof(dialogue));
    free(d);
    ((screen *) ld)->type = LABEL_DIALOGUE;
    ld->label = label;
    ld->ok = button_create((screen *) ld, act, "Ok", ((dialogue *) ld)->height - 5,
                           (((dialogue *) ld)->width - 12) / 2);
    ld->label_dialogue_get_input = label_dialogue_get_input;
    keypad(((screen *) ld)->win, TRUE);
    BUTTON_SET_FOCUS(ld->ok, true);
    label_dialogue_render(ld);
    return ld;
}

void label_dialogue_free(label_dialogue *ld)
{
    delwin(((screen *) ld)->win);
    free(ld);
}

void label_dialogue_render(label_dialogue *ld)
{
    DIALOGUE_RENDER((dialogue *) ld);
    BUTTON_RENDER(ld->ok);
    mvwprintw(((screen *) ld)->win, 5, 4, "%s", ld->label);
}

void label_dialogue_get_input(struct label_dialogue *ld)
{
     int c;

     c = wgetch(((screen *) ld)->win);
     switch (c) {
     case KEY_ENTER:
     case '\n':
     case KEY_ESC:
         pop_screen();
         ld->ok->action(NULL);
         break;
     default:
         break;
     }
}
