#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "dialogue.h"
#include "../util.h"

struct file_info {
    char *name;
    struct stat *stat;
};

enum file_selection_focus {
    FS_LIST,
    FS_INPUT,
    FS_OK,
    FS_CANCEL
};

static void dialogue_init(dialogue *d, char *title, int height, int width);
static void dialogue_set_title(dialogue *this, char *title);
static void dialogue_render(dialogue *this);
static void label_dialogue_render(label_dialogue *this);
static void label_dialogue_get_input(struct label_dialogue *this);
static void file_dialogue_render(file_dialogue *this);
static void file_dialogue_populate(file_dialogue *this, char *path);
static void file_dialogue_get_input(struct file_dialogue *this);
static void file_dialogue_print(struct file_dialogue *this, struct file_info *info, int i);
static void file_dialogue_update_input(struct file_dialogue *this, char *path);
static void file_dialogue_handle_enter(struct file_dialogue *this);
static void file_dialogue_update_focus(struct file_dialogue *this);
static void file_dialogue_handle_keydown(struct file_dialogue *this);
static void file_dialogue_handle_keyup(struct file_dialogue *this);

static int cmpstring(const void *p1, const void *p2)
{
    return strcmp((* (struct file_info **) p1)->name, (* (struct file_info **) p2)->name);
}

static void free_data(void *data)
{
    struct file_info *info = (struct file_info *) data;

    free(info->name);
    free(info->stat);
    free(info);
}

static void show_selectionbar(file_dialogue *fd, int line)
{
    mvwchgat(fd->list.win, line, 0, -1, A_NORMAL, 2, NULL);
}

static void remove_selectionbar(file_dialogue *fd, int line)
{
    struct file_info *info;

    info = (struct file_info *) vector_get_data(fd->files, fd->i);
    if (S_ISDIR(info->stat->st_mode)) {
        mvwchgat(fd->list.win, line, 0, -1, A_BOLD, 3, NULL);
    } else {
        mvwchgat(fd->list.win, line, 0, -1, A_NORMAL, 3, NULL);
    }
}

dialogue *dialogue_create(char *title)
{
    int my, mx;
    dialogue *d = malloc(sizeof(dialogue));

    getmaxyx(stdscr, my, mx);
    dialogue_init(d, title, my / 4, mx / 5 + 10);
    return d;
}

void dialogue_init(dialogue *d, char *title, int height, int width)
{
    int my, mx;

    getmaxyx(stdscr, my, mx);
    d->height = height;
    d->width = width;
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

label_dialogue *label_dialogue_create(char *title, char *label, button_action act, void *arg)
{
    label_dialogue *ld;
    int my, mx;

    getmaxyx(stdscr, my, mx);
    ld = malloc(sizeof(label_dialogue));
    dialogue_init((dialogue *) ld, title, my / 5, mx / 6 + 10);
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

file_dialogue *file_dialogue_create(char *title, enum file_selection_type type,
                                    char *path, button_action ok, button_action cancel)
{
    file_dialogue *fd;
    int my, mx;

    getmaxyx(stdscr, my, mx);
    fd = malloc(sizeof(file_dialogue));
    dialogue_init((dialogue *) fd, title, my / 3, mx / 5 + 10);
    getmaxyx(((screen *) fd)->win, my, mx);
    ((screen *) fd)->type = FILE_DIALOGUE;
    fd->file_dialogue_get_input = file_dialogue_get_input;
    fd->list_height = my - 10;
    fd->list.win = derwin(((screen *) fd)->win, fd->list_height, mx - 15, 3, 7);
    fd->input.win = derwin(((screen *) fd)->win, 1, mx - 15, fd->list_height + 4, 7);
    fd->i = 0;
    fd->num_files = 0;
    fd->top = 0;
    fd->files = vector_init(10);
    fd->ok = button_create((screen *) fd, ok, NULL, "Ok", my - 4, 7);
    fd->cancel = button_create((screen *) fd, cancel, NULL, "Cancel", my - 4, mx - 20);
    strncpy(fd->path, path, MAXPATH);
    scrollok(fd->list.win, TRUE);
    nodelay(fd->list.win, TRUE);
    keypad(fd->list.win, TRUE);
    file_dialogue_render(fd);
    fd->has_focus = FS_LIST;
    return fd;
}

void file_dialogue_free(file_dialogue *fd)
{
    if (fd) {
        delwin(((screen *) fd)->win);
        delwin(fd->list.win);
        delwin(fd->input.win);
        vector_free(fd->files, free_data);
        button_free(fd->ok);
        button_free(fd->cancel);
        free(fd);
    }
}

void file_dialogue_render(file_dialogue *this)
{
    int w;
    screen *scr;

    scr = (screen *) this;
    DIALOGUE_RENDER((dialogue *) this);
    wbkgd(this->list.win, COLOR_PAIR(3));
    wbkgd(this->input.win, COLOR_PAIR(12));
    w = getmaxx(scr->win) - 13;
    printat(scr->win, 2, 8, A_BOLD, "Name");
    printat(scr->win, 2, w, A_BOLD, "Size");
    mvwchgat(scr->win, 2, 7, w - 2, A_NORMAL, 12, NULL);
    file_dialogue_populate(this, this->path);
    BUTTON_RENDER(this->ok);
    BUTTON_RENDER(this->cancel);
    wrefresh(this->list.win);
    wrefresh(scr->win);
}

void file_dialogue_populate(file_dialogue *this, char *path)
{
    DIR *dir;
    struct dirent *ent;

    if ((dir = opendir(path))) {
        this->num_files = 0;
        if (vector_size(this->files) > 0) {
            if (this->i > 0) {
                remove_selectionbar(this, this->i);
                this->i = 0;
            }
            vector_clear(this->files, free_data);
        }
        while ((ent = readdir(dir))) {
            struct stat *buf;
            struct file_info *info;
            char filepath[MAXPATH + 1];

            if (strncmp(ent->d_name, ".", 1) == 0 &&
                strcmp(ent->d_name, "..") != 0) {
                continue;
            }
            info = malloc(sizeof(struct file_info));
            info->name = strdup(ent->d_name);
            buf = malloc(sizeof(struct stat));
            snprintf(filepath, MAXPATH, "%s/%s", path, info->name);
            lstat(filepath, buf);
            info->stat = buf;
            vector_push_back(this->files, info);
            this->num_files++;
        }
        qsort(vector_data(this->files), vector_size(this->files),
              sizeof(struct file_info *), cmpstring);
        for (int i = 0; i < vector_size(this->files); i++) {
            struct file_info *info;

            info = (struct file_info *) vector_get_data(this->files, i);
            file_dialogue_print(this, info, i);
        }
        file_dialogue_update_input(this, this->path);
        show_selectionbar(this, this->i);
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
        this->cancel->action(NULL);
        break;
    case KEY_UP:
        file_dialogue_handle_keyup(this);
        break;
    case KEY_DOWN:
        file_dialogue_handle_keydown(this);
        break;
    case KEY_ENTER:
    case '\n':
        file_dialogue_handle_enter(this);
        break;
    case '\t':
        file_dialogue_update_focus(this);
        break;
    case '\b':
    case KEY_BACKSPACE:
        if (this->has_focus == 1) {
            int y, x;

            getyx(this->input.win, y, x);
            if (x > 0) {
                int n;

                n = strlen(this->path);
                if (n > 0) {
                    this->path[n - 1] = '\0';
                }
                mvwdelch(this->input.win, y, x - 1);
                wrefresh(this->input.win);
            }
        }
        break;
    default:
        if (this->has_focus == 1 && isprint(c)) {
            snprintcat(this->path, MAXPATH, "%c", c);
            waddch(this->input.win, c);
            wrefresh(this->input.win);
        }
        break;
    }
}

void file_dialogue_handle_enter(struct file_dialogue *this)
{
    struct file_info *info;

    info = (struct file_info *) vector_get_data(this->files, this->i);
    switch (this->has_focus) {
    case FS_LIST:
        if (S_ISDIR(info->stat->st_mode)) {
            if (strcmp(info->name, "..") == 0) {
                get_directory_part(this->path); /* remove ".." */
                if (strcmp(this->path, "/") != 0) {
                    get_directory_part(this->path); /* go up dir */
                }
            }
            werase(this->list.win);
            file_dialogue_populate(this, this->path);
            wrefresh(this->list.win);
        } else {
            pop_screen();
            this->ok->action(this->path);
        }
        break;
    case FS_INPUT:
    {
        int n = strlen(this->path);

        if (n > 0) {
            struct stat buf[sizeof(struct stat)];

            if (this->path[n - 1] == '/') {
                this->path[n - 1] = '\0';
            }
            lstat(this->path, buf);
            if (S_ISDIR(buf->st_mode)) {
                werase(this->list.win);
                file_dialogue_populate(this, this->path);
                wrefresh(this->list.win);
            } else {
                pop_screen();
                this->ok->action(this->path);
            }
        }
        curs_set(0);
        this->has_focus = FS_LIST;
        break;
    }
    case FS_OK:
        pop_screen();
        this->ok->action(this->path);
        break;
    case FS_CANCEL:
        pop_screen();
        this->cancel->action(NULL);
        break;
    default:
        break;
    }
}

void file_dialogue_print(struct file_dialogue *this, struct file_info *info, int i)
{
    int w;

    if (S_ISDIR(info->stat->st_mode)) {
        w = getmaxx(this->list.win) - strlen(info->name) - 2;
        printat(this->list.win, i, 1, A_BOLD, "%s%*d", info->name, w, info->stat->st_size);
    } else {
        w = getmaxx(this->list.win) - strlen(info->name) - 2;
        mvwprintw(this->list.win, i, 1, "%s%*d", info->name, w, info->stat->st_size);
    }
}

void file_dialogue_update_input(struct file_dialogue *this, char *path)
{
    struct file_info *info;

    info = (struct file_info *) vector_get_data(this->files, this->i);
    snprintcat(path, MAXPATH, "/%s", info->name);
    werase(this->input.win);
    waddstr(this->input.win, path);
    wrefresh(this->input.win);
}

void file_dialogue_update_focus(struct file_dialogue *this)
{
    this->has_focus = (this->has_focus + 1) % 4;

    switch (this->has_focus) {
    case FS_LIST:
        BUTTON_SET_FOCUS(this->ok, false);
        BUTTON_SET_FOCUS(this->cancel, false);
        if (this->num_files) {
            file_dialogue_populate(this, get_directory_part(this->path));
        } else {
            file_dialogue_populate(this, this->path);
        }
        BUTTON_RENDER(this->ok);
        BUTTON_RENDER(this->cancel);
        wrefresh(this->list.win);
        wrefresh(((screen *) this)->win);
        break;
    case FS_INPUT:
        wmove(((screen *) this)->win, this->list_height + 4, strlen(this->path) + 7);
        curs_set(1);
        remove_selectionbar(this, this->i);
        wrefresh(this->input.win);
        wrefresh(this->list.win);
        wrefresh(((screen *) this)->win);
        break;
    case FS_OK:
        curs_set(0);
        BUTTON_SET_FOCUS(this->ok, true);
        BUTTON_RENDER(this->ok);
        break;
    case FS_CANCEL:
        BUTTON_SET_FOCUS(this->ok, false);
        BUTTON_SET_FOCUS(this->cancel, true);
        BUTTON_RENDER(this->ok);
        BUTTON_RENDER(this->cancel);
        break;
    default:
        break;
    }
}

void file_dialogue_handle_keydown(struct file_dialogue *this)
{
    if (this->has_focus == FS_LIST) {
        if (this->i >= this->top + this->list_height - 1 &&
            this->i < this->num_files - 1) {
            remove_selectionbar(this, this->i - this->top);
            wscrl(this->list.win, 1);
            this->i++;
            this->top++;
            file_dialogue_print(this, vector_get_data(this->files, this->i), this->list_height - 1);
            file_dialogue_update_input(this, get_directory_part(this->path));
            show_selectionbar(this, this->list_height - 1);
        } else if (this->i < this->num_files - 1) {
            remove_selectionbar(this, this->i - this->top);
            show_selectionbar(this, this->i - this->top + 1);
            this->i++;
            file_dialogue_update_input(this, get_directory_part(this->path));
        }
        wrefresh(this->list.win);
    } else if (this->has_focus == FS_INPUT && this->i < this->num_files - 1) {
        this->i++;
        file_dialogue_update_input(this, get_directory_part(this->path));
    }
}

void file_dialogue_handle_keyup(struct file_dialogue *this)
{
    if (this->has_focus == FS_LIST) {

        remove_selectionbar(this, this->i - this->top);
        if (this->top == 0 && this->i - 1 < 0) {

        } else if (this->i == this->top) {
            wscrl(this->list.win, -1);
            this->top--;
            this->i--;
            file_dialogue_print(this, vector_get_data(this->files, this->i), 0);
            file_dialogue_update_input(this, get_directory_part(this->path));
        } else {
            this->i--;
            file_dialogue_update_input(this, get_directory_part(this->path));
        }
        show_selectionbar(this, this->i - this->top);
        wrefresh(this->list.win);
    } else if (this->has_focus == FS_INPUT && this->i > 0) {
        this->i--;
        file_dialogue_update_input(this, get_directory_part(this->path));
    }
}
