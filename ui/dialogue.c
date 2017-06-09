#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include "dialogue.h"

static char file[MAXPATH + 1];
static int num_chars;

static void dialogue_init(dialogue *d, char *title);
static void dialogue_set_title(dialogue *this, char *title);
static void dialogue_render(dialogue *this);
static void input_dialogue_get_input(input_dialogue *this);
static void input_dialogue_set_input(input_dialogue *this, char *input);
static void input_dialogue_render(input_dialogue *this);
static void input_dialogue_set_button_action(input_dialogue *this,
                                                  button_action ok, void *arg1,
                                                  button_action cancel, void *arg2);
static void input_dialogue_handle_enter(input_dialogue *this);
static void label_dialogue_render(label_dialogue *this);
static void label_dialogue_get_input(struct label_dialogue *this);

static void file_dialogue_render(file_dialogue *this);
static void file_dialogue_populate(file_dialogue *this, char *path);
static void file_dialogue_get_input(struct file_dialogue *this);

static int cmpstring(const void *p1, const void *p2)
{
    return strcmp(* (const char **) p1, * (const char **) p2);
}

dialogue *dialogue_create(char *title)
{
    dialogue *d = malloc(sizeof(dialogue));

    dialogue_init(d, title);
    return d;
}

void dialogue_init(dialogue *d, char *title)
{
    int my, mx;

    getmaxyx(stdscr, my, mx);
    d->height  = my / 5;
    d->width = mx / 5 + 10;
    d->screen_base.focus = false;
    d->screen_base.win = newwin(d->height, d->width, (my - d->height) / 2, (mx - d->width) / 2);
    d->title = title;
    d->dialogue_set_title = dialogue_set_title;
    d->dialogue_render = dialogue_render;
}

void dialogue_free(dialogue *d)
{
    if (d) {
        delwin(((screen *) d)->win);
        free(d);
    }
}

void dialogue_set_title(dialogue *this, char *title)
{
    this->title = title;
}

void dialogue_render(dialogue *this)
{
    int mx;
    WINDOW *win;
    int len;

    win = ((screen *) this)->win;
    mx = getmaxx(win);
    box(win, 0, 0);
    wbkgd(win, COLOR_PAIR(11));
    if (this->title) {
        len = strlen(this->title);
        mvwprintw(win, 0, (mx - len) / 2, this->title);
        printat(win, 0, (mx - len) / 2, A_BOLD, this->title);
    }
    wrefresh(win);
}

input_dialogue *input_dialogue_create(char *title, button_action ok, button_action cancel)
{
    input_dialogue *id;
    int my, mx;

    id = malloc(sizeof(input_dialogue));
    dialogue_init((dialogue *) id, title);
    getmaxyx(((screen *) id)->win, my, mx);
    ((screen *) id)->type = INPUT_DIALOGUE;
    id->ok = button_create((screen *) id, ok, NULL, "Ok", my - 5, 4);
    id->cancel = button_create((screen *) id, cancel, NULL, "Cancel", my - 5, mx - 16);
    id->input.win = derwin(((screen *) id)->win, 1, mx - 8, 6, 4);
    id->input.focus = false;
    id->has_focus = 0;
    id->input_dialogue_set_button_action = input_dialogue_set_button_action;
    id->input_dialogue_get_input = input_dialogue_get_input;
    id->input_dialogue_set_input = input_dialogue_set_input;
    id->input_dialogue_render = input_dialogue_render;
    nodelay(id->input.win, TRUE);
    keypad(id->input.win, TRUE);
    waddstr(id->input.win, file);
    num_chars = strlen(file);
    input_dialogue_render(id);
    return id;
}

void input_dialogue_free(input_dialogue *id)
{
    if (id) {
        button_free(id->ok);
        button_free(id->cancel);
        delwin(id->input.win);
        delwin(((screen *) id)->win);
        free(id);
    }
}

void input_dialogue_set_input(input_dialogue *this, char *input)
{
    strncpy(file, input, MAXPATH);
    werase(this->input.win);
    waddstr(this->input.win, file);
    num_chars = strlen(file);
    input_dialogue_render(this);
}

void input_dialogue_set_button_action(input_dialogue *this, button_action ok, void *arg1,
                                           button_action cancel, void *arg2)
{
    BUTTON_SET_ACTION(this->ok, ok, arg1);
    BUTTON_SET_ACTION(this->cancel, cancel, arg2);
}

void input_dialogue_get_input(input_dialogue *this)
{
    int c;

    c = wgetch(this->input.win);
    switch (c) {
    case '\t':
        this->has_focus = (this->has_focus + 1) % 3;
        input_dialogue_render(this);
        break;
    case KEY_ENTER:
    case '\n':
        input_dialogue_handle_enter(this);
        break;
    case KEY_ESC:
        curs_set(0);
        pop_screen();
        this->cancel->action(NULL);
        break;
    case '\b':
    case KEY_BACKSPACE:
    {
        int y, x;

        getyx(this->input.win, y, x);
        if (x > 0) {
            if (num_chars > 0) --num_chars;
            mvwdelch(this->input.win, y, x - 1);
            wrefresh(this->input.win);
        }
        break;
    }
    default:
        if (isprint(c)) {
            file[num_chars++] = (char) c;
            waddch(this->input.win, c);
            wrefresh(this->input.win);
        }
        break;
    }
}

void input_dialogue_render(input_dialogue *this)
{
    werase(((container *) this->ok)->win);
    werase(((container *) this->cancel)->win);
    DIALOGUE_RENDER((dialogue *) this);
    mvwprintw(((screen *) this)->win, 5, 4, "File path: ");
    wbkgd(this->input.win, COLOR_PAIR(1));

    switch (this->has_focus) {
    case 0:
        wmove(((screen *) this)->win, 6, num_chars + 4);
        curs_set(1);
        BUTTON_SET_FOCUS(this->ok, false);
        BUTTON_SET_FOCUS(this->cancel, false);
        break;
    case 1:
        curs_set(0);
        BUTTON_SET_FOCUS(this->ok, true);
        break;
    case 2:
        BUTTON_SET_FOCUS(this->ok, false);
        BUTTON_SET_FOCUS(this->cancel, true);
        break;
    }
    BUTTON_RENDER(this->ok);
    BUTTON_RENDER(this->cancel);
    wrefresh(this->input.win);
    wrefresh(((screen *) this)->win);
}

void input_dialogue_handle_enter(input_dialogue *this)
{
    switch (this->has_focus) {
    case 0:
    case 1:
        if (num_chars) {
            file[num_chars] = '\0';
            curs_set(0);
            pop_screen();
            this->ok->action(file);
        }
        break;
    case 2:
        curs_set(0);
        pop_screen();
        this->cancel->action(NULL);
        break;
    }
}

label_dialogue *label_dialogue_create(char *title, char *label, button_action act, void *arg)
{
    label_dialogue *ld;

    ld = malloc(sizeof(label_dialogue));
    dialogue_init((dialogue *) ld, title);
    ((screen *) ld)->type = LABEL_DIALOGUE;
    ld->label = label;
    ld->ok = button_create((screen *) ld, act, arg, "Ok", ((dialogue *) ld)->height - 5,
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

void label_dialogue_render(label_dialogue *this)
{
    DIALOGUE_RENDER((dialogue *) this);
    BUTTON_RENDER(this->ok);
    mvwprintw(((screen *) this)->win, 5, 4, "%s", this->label);
}

void label_dialogue_get_input(struct label_dialogue *this)
{
     int c;

     c = wgetch(((screen *) this)->win);
     switch (c) {
     case KEY_ENTER:
     case '\n':
     case KEY_ESC:
         pop_screen();
         this->ok->action(this->ok->argument);
         break;
     default:
         break;
     }
}

file_dialogue *file_dialogue_create(char *title, char *path)
{
    file_dialogue *fd;
    int my, mx;

    fd = malloc(sizeof(file_dialogue));
    dialogue_init((dialogue *) fd, title);
    getmaxyx(((screen *) fd)->win, my, mx);
    ((screen *) fd)->type = FILE_DIALOGUE;
    fd->file_dialogue_get_input = file_dialogue_get_input;
    fd->list_height = 8;
    fd->list.win = derwin(((screen *) fd)->win, fd->list_height, mx - 15, 3, 7);
    fd->list.focus = true;
    fd->i = 0;
    fd->num_files = 0;
    fd->top = 0;
    fd->files = vector_init(10);
    strncpy(fd->path, path, MAXPATH);
    scrollok(fd->list.win, TRUE);
    nodelay(fd->list.win, TRUE);
    keypad(fd->list.win, TRUE);
    file_dialogue_render(fd);
    return fd;
}

void file_dialogue_free(file_dialogue *fd)
{
    if (fd) {
        delwin(((screen *) fd)->win);
        delwin(fd->list.win);
        vector_free(fd->files, free);
        free(fd);
    }
}

void file_dialogue_render(file_dialogue *this)
{
    DIALOGUE_RENDER((dialogue *) this);
    wbkgd(this->list.win, COLOR_PAIR(11) | A_BOLD);
    file_dialogue_populate(this, this->path);
    wrefresh(this->list.win);
    wrefresh(((screen *) this)->win);
}

void file_dialogue_populate(file_dialogue *this, char *path)
{
    DIR *dir;
    struct dirent *ent;

    if ((dir = opendir(path))) {
        this->num_files = 0;
        while ((ent = readdir(dir))) {
            char *data;

            if (strcmp(ent->d_name, ".") == 0) continue;
            data = strdup(ent->d_name);
            vector_push_back(this->files, data);
            this->num_files++;
        }
        qsort(vector_data(this->files), vector_size(this->files),
              sizeof(char *), cmpstring);
        for (int i = 0; i < vector_size(this->files); i++) {
            mvwprintw(this->list.win, i, 2, "%s", vector_get_data(this->files, i));
        }
        mvwchgat(this->list.win, this->i, 0, -1, A_NORMAL, 2, NULL);
        closedir(dir);
    }
}

void file_dialogue_get_input(struct file_dialogue *this)
{
    int c;

    c = wgetch(this->list.win);
    switch (c) {
    case KEY_ESC:
        pop_screen();
        break;
    case KEY_UP:
        mvwchgat(this->list.win, this->i - this->top, 0, -1, A_BOLD, 11, NULL);
        if (this->top == 0 && this->i - 1 < 0) {
            //this->i = this->num_files - 1;
        } else if (this->i == this->top) {
            wscrl(this->list.win, -1);
            this->top--;
            this->i--;
            mvwprintw(this->list.win, 0, 2, "%s", vector_get_data(this->files, this->i));
        } else {
            this->i = (this->i - 1) % this->num_files;
        }
        mvwchgat(this->list.win, this->i - this->top, 0, -1, A_BOLD, 2, NULL);
        wrefresh(this->list.win);
        break;
    case KEY_DOWN:
        if (this->i >= this->top + this->list_height - 1 &&
            this->i < this->num_files - 1) {
            mvwchgat(this->list.win, this->i - this->top, 0, -1, A_BOLD, 11, NULL);
            wscrl(this->list.win, 1);
            //this->i = (this->i + 1) % this->num_files;
            this->i++;
            this->top++;
            mvwprintw(this->list.win, this->list_height - 1, 2, "%s",
                      vector_get_data(this->files, this->i));
            mvwchgat(this->list.win, this->list_height - 1, 0, -1, A_BOLD, 2, NULL);
        } else if (this->i < this->num_files - 1) {
            mvwchgat(this->list.win, this->i - this->top, 0, -1, A_BOLD, 11, NULL);
            mvwchgat(this->list.win, this->i - this->top + 1, 0, -1, A_BOLD, 2, NULL);
            this->i = (this->i + 1) % this->num_files;
        }
        wrefresh(this->list.win);
        break;
    default:
        break;
    }
}
