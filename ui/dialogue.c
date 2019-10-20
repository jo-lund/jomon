#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "dialogue.h"
#include "../util.h"

#define FORMAT_BUF_LEN 7
#define FILE_INPUT_TEXT "Filename: "
#define FILE_INPUT_TEXTLEN 10

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
static void label_dialogue_get_input(screen *s);
static void label_dialogue_set_action(label_dialogue *ld, button_action act, void *arg);
static void file_dialogue_render(file_dialogue *this);
static void file_dialogue_populate(file_dialogue *this, char *path);
static void file_dialogue_get_input(screen *s);
static void file_dialogue_print(struct file_dialogue *this, struct file_info *info, int i);
static void file_dialogue_update_input(struct file_dialogue *this);
static void file_dialogue_update_dir(struct file_dialogue *this, char *path);
static void file_dialogue_handle_enter(struct file_dialogue *this);
static void file_dialogue_update_focus(struct file_dialogue *this);
static void file_dialogue_handle_keydown(struct file_dialogue *this);
static void file_dialogue_handle_keyup(struct file_dialogue *this);
static void progress_dialogue_render(progress_dialogue *this);
static void progress_dialogue_update(progress_dialogue *this, int n);

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
    mvwchgat(fd->list.win, line, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(SELECTIONBAR)), NULL);
}

static void remove_selectionbar(file_dialogue *fd, int line)
{
    struct file_info *info;

    info = (struct file_info *) vector_get_data(fd->files, fd->i);
    if (S_ISDIR(info->stat->st_mode)) {
        mvwchgat(fd->list.win, line, 0, -1, A_BOLD, PAIR_NUMBER(get_theme_colour(FD_TEXT)), NULL);
    } else {
        mvwchgat(fd->list.win, line, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(FD_TEXT)), NULL);
    }
}

dialogue *dialogue_create(char *title)
{
    int my, mx;
    static screen_operations op;
    dialogue *d = malloc(sizeof(dialogue));

    op = SCREEN_OPS(.screen_free = dialogue_free);
    d->screen_base.op = &op;
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

void dialogue_free(screen *s)
{
    if (s) {
        delwin(s->win);
        free((dialogue *) s);
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
    wbkgd(win, get_theme_colour(DIALOGUE_BKGD));
    if (this->title) {
        len = strlen(this->title);
        mvwprintw(win, 0, (mx - len) / 2, this->title);
        printat(win, 0, (mx - len) / 2, A_BOLD, this->title);
    }
}

label_dialogue *label_dialogue_create(char *title, char *label, button_action act, void *arg)
{
    label_dialogue *ld;
    int my, mx;
    static screen_operations op;

    getmaxyx(stdscr, my, mx);
    ld = malloc(sizeof(label_dialogue));
    op = SCREEN_OPS(.screen_free = label_dialogue_free,
                    .screen_get_input = label_dialogue_get_input);
    ld->dialogue_base.screen_base.op = &op;
    dialogue_init((dialogue *) ld, title, my / 5, mx / 6 + 10);
    ld->label = label;
    ld->ok = button_create((screen *) ld, act, arg, "Ok", ((dialogue *) ld)->height - 5,
                           (((dialogue *) ld)->width - 12) / 2);
    ld->label_dialogue_set_action = label_dialogue_set_action;
    keypad(((screen *) ld)->win, TRUE);
    BUTTON_SET_FOCUS(ld->ok, true);
    label_dialogue_render(ld);
    return ld;
}

void label_dialogue_free(screen *s)
{
    delwin(s->win);
    button_free(((label_dialogue *) s)->ok);
    free((label_dialogue *) s);
}

void label_dialogue_render(label_dialogue *this)
{
    DIALOGUE_RENDER((dialogue *) this);
    BUTTON_RENDER(this->ok);
    mvwprintw(((screen *) this)->win, 5, 4, "%s", this->label);
}

void label_dialogue_set_action(label_dialogue *ld, button_action act, void *arg)
{
    ld->ok->button_set_action(ld->ok, act, arg);
}

void label_dialogue_get_input(screen *s)
{
     int c;
     label_dialogue *ld;

     ld = (label_dialogue *) s;
     c = wgetch(s->win);
     switch (c) {
     case KEY_ENTER:
     case '\n':
     case KEY_ESC:
         pop_screen();
         if (ld->ok->action) {
             ld->ok->action(ld->ok->argument);
         }
         break;
     default:
         break;
     }
}

file_dialogue *file_dialogue_create(char *title, enum file_selection_type type UNUSED,
                                    char *path, button_action ok, button_action cancel)
{
    file_dialogue *fd;
    int my, mx;
    static screen_operations op;

    getmaxyx(stdscr, my, mx);
    fd = malloc(sizeof(file_dialogue));
    op = SCREEN_OPS(.screen_free = file_dialogue_free,
                     .screen_get_input = file_dialogue_get_input);
    fd->dialogue_base.screen_base.op = &op;
    dialogue_init((dialogue *) fd, title, my / 3, mx / 5 + 10);
    getmaxyx(((screen *) fd)->win, my, mx);
    fd->list_height = my - 10;
    fd->list.win = derwin(((screen *) fd)->win, fd->list_height, mx - 15, 3, 7);
    fd->dir.win = derwin(((screen *) fd)->win, 1, mx - 15, fd->list_height + 4, 7);
    fd->input.win = derwin(((screen *) fd)->win, 1, mx - 15, fd->list_height + 6, 7);
    fd->i = 0;
    fd->num_files = 0;
    fd->top = 0;
    fd->has_focus = FS_LIST;
    fd->files = vector_init(10);
    fd->ok = button_create((screen *) fd, ok, NULL, "Ok", my - 2, 7);
    fd->cancel = button_create((screen *) fd, cancel, NULL, "Cancel", my - 2, mx - 20);
    strncpy(fd->path, path, MAXPATH);
    snprintcat(fd->path, MAXPATH, "/");
    scrollok(fd->list.win, TRUE);
    nodelay(fd->list.win, TRUE);
    keypad(fd->list.win, TRUE);
    file_dialogue_render(fd);
    return fd;
}

void file_dialogue_free(screen *s)
{
    if (s) {
        file_dialogue *fd = (file_dialogue *) s;

        delwin(s->win);
        delwin(fd->list.win);
        delwin(fd->dir.win);
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
    wbkgd(this->list.win, get_theme_colour(FD_LIST_BKGD));
    wbkgd(this->dir.win, get_theme_colour(FD_INPUT_BKGD));
    wbkgd(this->input.win, get_theme_colour(FD_INPUT_BKGD));
    w = getmaxx(scr->win) - 13;
    printat(scr->win, 2, 8, A_BOLD, "Name");
    printat(scr->win, 2, w, A_BOLD, "Size");
    mvwchgat(scr->win, 2, 7, w - 2, A_NORMAL, PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
    wprintw(this->input.win, FILE_INPUT_TEXT);
    file_dialogue_populate(this, this->path);
    file_dialogue_update_dir(this, this->path);
    BUTTON_RENDER(this->ok);
    BUTTON_RENDER(this->cancel);
    wrefresh(this->list.win);
}

void file_dialogue_populate(file_dialogue *this, char *path)
{
    DIR *dir;
    struct dirent *ent;
    vector_t *entries;

    entries = vector_init(10);
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
            if (S_ISDIR(info->stat->st_mode)) {
                vector_push_back(this->files, info);
            } else {
                vector_push_back(entries, info);
            }
            this->num_files++;
        }
        /* sort directories */
        qsort(vector_data(this->files), vector_size(this->files),
              sizeof(struct file_info *), cmpstring);

        /* sort regular files */
        qsort(vector_data(entries), vector_size(entries),
              sizeof(struct file_info *), cmpstring);

        /* insert regular files at end */
        for (int i = 0; i < vector_size(entries); i++) {
            vector_push_back(this->files, vector_get_data(entries, i));
        }
        vector_free(entries, NULL);
        for (int i = 0; i < vector_size(this->files); i++) {
            struct file_info *info;

            info = (struct file_info *) vector_get_data(this->files, i);
            file_dialogue_print(this, info, i);
        }
        show_selectionbar(this, this->i);
        closedir(dir);
    }
}

void file_dialogue_get_input(screen *s)
{
    int c;
    file_dialogue *fd;

    fd = (file_dialogue *) s;
    c = wgetch(fd->list.win);
    switch (c) {
    case KEY_ESC:
        curs_set(0);
        pop_screen();
        fd->cancel->action(NULL);
        break;
    case KEY_UP:
        file_dialogue_handle_keyup(fd);
        break;
    case KEY_DOWN:
        file_dialogue_handle_keydown(fd);
        break;
    case KEY_LEFT:
        if (fd->has_focus == FS_INPUT) {
            int y, x;

            getyx(fd->input.win, y, x);
            if (x > FILE_INPUT_TEXTLEN) {
                wmove(fd->input.win, y, --x);
                wrefresh(fd->input.win);
            }
        }
        break;
    case KEY_RIGHT:
        if (fd->has_focus == FS_INPUT) {
            int y, x, maxx;

            getyx(fd->input.win, y, x);
            maxx = getmaxx(fd->input.win);
            if (x < maxx) {
                wmove(fd->input.win, y, ++x);
                wrefresh(fd->input.win);
            }
        }
        break;
    case KEY_ENTER:
    case '\n':
        file_dialogue_handle_enter(fd);
        break;
    case '\t':
        file_dialogue_update_focus(fd);
        break;
    case '\b':
    case KEY_BACKSPACE:
        if (fd->has_focus == FS_INPUT) {
            int y, x;

            getyx(fd->input.win, y, x);
            if (x > FILE_INPUT_TEXTLEN) {
                int n;

                n = strlen(fd->path);
                if (n > 0) {
                    fd->path[n - 1] = '\0';
                }
                mvwdelch(fd->input.win, y, x - 1);
                wrefresh(fd->input.win);
            }
        }
        break;
    case KEY_DC:
        if (fd->has_focus == FS_INPUT) {
            int y UNUSED;
            int x;
            int len = 0;
            char buf[MAXPATH];

            getyx(fd->input.win, y, x);
            winnstr(fd->input.win, buf, MAXPATH);
            len = strlen(buf);
            if (x < FILE_INPUT_TEXTLEN + len) {
                wdelch(fd->input.win);
                wrefresh(fd->input.win);
            }
        }
        break;
    default:
        if (fd->has_focus == FS_INPUT && isprint(c)) {
            snprintcat(fd->path, MAXPATH, "%c", c);
            waddch(fd->input.win, c);
            wrefresh(fd->input.win);
        }
        break;
    }
}

void file_dialogue_handle_enter(struct file_dialogue *this)
{
    struct file_info *info;

    curs_set(0);
    info = (struct file_info *) vector_get_data(this->files, this->i);
    switch (this->has_focus) {
    case FS_LIST:
        if (S_ISDIR(info->stat->st_mode)) {
            if (strcmp(info->name, "..") == 0) {
                get_directory_part(this->path); /* remove ".." */
                if (strcmp(this->path, "/") != 0) {
                    get_directory_part(this->path); /* go up dir */
                    snprintcat(this->path, MAXPATH, "/");
                }
            } else {
                snprintcat(this->path, MAXPATH, "%s/", info->name);
            }
            werase(this->list.win);
            this->top = 0;
            file_dialogue_populate(this, this->path);
            wrefresh(this->list.win);
            file_dialogue_update_dir(this, this->path);
        } else {
            snprintcat(this->path, MAXPATH, "%s", info->name);
            pop_screen();
            this->ok->action(this->path);
        }
        break;
    case FS_INPUT:
    {
        int n = strlen(this->path);

        if (n > 0) {
            pop_screen();
            this->ok->action(this->path);
            return;
        }
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
    char buf[FORMAT_BUF_LEN];

    if (S_ISDIR(info->stat->st_mode)) {
        w = getmaxx(this->list.win) - strlen(info->name) - 2;
        printat(this->list.win, i, 1, A_BOLD | get_theme_colour(FD_TEXT), "%s%*s", info->name, w,
                format_bytes(info->stat->st_size, buf, FORMAT_BUF_LEN));
    } else {
        w = getmaxx(this->list.win) - strlen(info->name) - 2;
        printat(this->list.win, i, 1, get_theme_colour(FD_TEXT), "%s%*s", info->name, w,
                format_bytes(info->stat->st_size, buf, FORMAT_BUF_LEN));
    }
}

void file_dialogue_update_input(struct file_dialogue *this)
{
    struct file_info *info;

    info = (struct file_info *) vector_get_data(this->files, this->i);
    wmove(this->input.win, 0, FILE_INPUT_TEXTLEN);
    wclrtoeol(this->input.win);
    if (!S_ISDIR(info->stat->st_mode)) {
        waddstr(this->input.win, info->name);
    }
    wrefresh(this->input.win);

}

void file_dialogue_update_dir(struct file_dialogue *this, char *path)
{
    struct file_info *info;

    info = (struct file_info *) vector_get_data(this->files, this->i);
    if (S_ISDIR(info->stat->st_mode)) {
        werase(this->dir.win);
        waddstr(this->dir.win, path);
        wrefresh(this->dir.win);
    }
}

void file_dialogue_update_focus(struct file_dialogue *this)
{
    this->has_focus = (this->has_focus + 1) % 4;

    switch (this->has_focus) {
    case FS_LIST:
        BUTTON_SET_FOCUS(this->ok, false);
        BUTTON_SET_FOCUS(this->cancel, false);
        show_selectionbar(this, this->i - this->top);
        BUTTON_RENDER(this->ok);
        BUTTON_RENDER(this->cancel);
        wrefresh(this->list.win);
        wrefresh(((screen *) this)->win);
        break;
    case FS_INPUT:
        wmove(((screen *) this)->win, this->list_height + 6, FILE_INPUT_TEXTLEN + 7);
        curs_set(1);
        remove_selectionbar(this, this->i - this->top);
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
            file_dialogue_update_input(this);
            show_selectionbar(this, this->list_height - 1);
        } else if (this->i < this->num_files - 1) {
            remove_selectionbar(this, this->i - this->top);
            show_selectionbar(this, this->i - this->top + 1);
            this->i++;
            file_dialogue_update_input(this);
        }
        wrefresh(this->list.win);
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
            file_dialogue_update_input(this);
        } else {
            this->i--;
            file_dialogue_update_input(this);
        }
        show_selectionbar(this, this->i - this->top);
        wrefresh(this->list.win);
    }
}

progress_dialogue *progress_dialogue_create(char *title, int size)
{
    progress_dialogue *pd;
    int my, mx;
    static screen_operations op;

    getmaxyx(stdscr, my, mx);
    pd = malloc(sizeof(progress_dialogue));
    op = SCREEN_OPS(.screen_free = progress_dialogue_free);
    pd->dialogue_base.screen_base.op = &op;
    dialogue_init((dialogue *) pd, title, my / 5, mx / 6);
    pd->progress_dialogue_update = progress_dialogue_update;
    pd->size = size;
    pd->percent = 0;
    pd->sum = 0;
    pd->idx = 0;
    pd->ypos = (my / 5) / 2 - 1;
    pd->xpos = ((mx / 6) - 28) / 2;
    dialogue_render((dialogue *) pd);
    progress_dialogue_render(pd);
    return pd;
}

void progress_dialogue_free(screen *s)
{
    if (s) {
        delwin(s->win);
        free((progress_dialogue *) s);
    }
}

void progress_dialogue_update(progress_dialogue *this, int n)
{
    int tmp;

    this->sum += n;
    tmp = ((float) this->sum / this->size) * 100;
    if (tmp != this->percent) {
        this->percent = tmp;
        progress_dialogue_render(this);
    }
}

void progress_dialogue_render(progress_dialogue *this)
{
    int width;

    width = this->percent / 5;
    mvwprintw(((screen *) this)->win, this->ypos, this->xpos, "%d %%", this->percent);
    if (this->idx < 1) {
        mvwprintw(((screen *) this)->win, this->ypos, this->xpos + 6, "[");
        mvwprintw(((screen *) this)->win, this->ypos, this->xpos + 27, "]");
        this->idx++;
    }
    while (this->idx < width + 1) {
        mvwprintw(((screen *) this)->win, this->ypos, this->idx + this->xpos + 6, "#");
        this->idx++;
    }
    wrefresh(((screen *) this)->win);
}
