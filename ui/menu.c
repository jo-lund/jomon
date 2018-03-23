#include <stdlib.h>
#include <string.h>
#include "menu.h"
#include "layout_int.h"

extern WINDOW *status;

static char *selected_txt = "[x] ";
static char *unselected_txt = "[ ] ";

typedef struct option_elem {
    char *txt;
    bool selected;
} option_elem;

struct option_menu {
    menu_type type;
    WINDOW *frame;
    WINDOW *content;
    WINDOW *wheader;
    char *header;
    option_elem *opts;
    int num_opts;
    list_t *subopts;
    int i;
    int previ;
    int x;
    bool focus;
    bool is_suboption;
    menu_handler handler;
};

static void main_menu_get_input(screen *s);
static void main_menu_refresh(screen *s);
static void main_menu_render(screen *s);
static void print_menu(list_t *items);
static void handle_new_focus(screen *s, int c);
static void free_option_menu(void *d);
static int get_cols(menu_type type, char **opts, int num_opts);
static void handle_selectionbar(option_menu *om, int c);

static void show_selectionbar(WINDOW *win, int line)
{
    mvwchgat(win, line, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(MENU_SELECTIONBAR)), NULL);
}

static void remove_selectionbar(WINDOW *win, int line)
{
    mvwchgat(win, line, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(MENU_BACKGROUND)), NULL);
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
    menu->base.win = newwin(1, mx, my - 1, 0);
    menu->base.focus = false;
    menu->update = true;
    menu->opt = list_init(NULL);
    return menu;
}

option_menu *main_menu_add_options(main_menu *menu, menu_type type, char *header,
                                   char **opts, int num_opts, menu_handler fn)
{
    option_menu *om;
    int cols = get_cols(type, opts, num_opts);
    int rows = num_opts + 2;;
    int my = getmaxy(stdscr);

    om = calloc(1, sizeof(option_menu));
    om->type = type;
    om->header = header;
    om->opts = calloc(num_opts, sizeof(option_elem));
    for (int i = 0; i < num_opts; i++) {
        om->opts[i].txt = opts[i];
        om->opts[i].selected = false;
    }
    om->num_opts = num_opts;
    om->x = 12 * list_size(menu->opt); /* TODO: Adjust this according to header */
    om->frame = newwin(rows, cols, my - (rows + 1), om->x);
    om->content = derwin(om->frame, rows - 2, cols - 2, 1, 1);
    om->wheader = derwin(menu->base.win, 1, strlen(header) + 2, 0,
                         1 + 12 * (list_size(menu->opt)));
    om->handler = fn;
    box(om->frame, 0, 0);
    nodelay(om->frame, TRUE);
    keypad(om->frame, TRUE);
    list_push_back(menu->opt, om);
    return om;
}

option_menu *main_menu_add_suboptions(option_menu *om, menu_type type, int sub_idx,
                                      char **opts, int num_opts, menu_handler fn)
{
    option_menu *sub;
    int cols = get_cols(type, opts, num_opts);
    int rows = num_opts + 2;;
    int my = getmaxy(stdscr);

    sub = calloc(1, sizeof(option_menu));
    sub->type = type;
    sub->opts = calloc(num_opts, sizeof(option_elem));
    for (int i = 0; i < num_opts; i++) {
        sub->opts[i].txt = opts[i];
        sub->opts[i].selected = false;
    }
    sub->num_opts = num_opts;
    sub->frame = newwin(rows, cols, my - om->num_opts - num_opts - 3 + sub_idx,
                        getmaxx(om->frame) + om->x);
    sub->content = derwin(sub->frame, rows - 2, cols - 2, 1, 1);
    sub->is_suboption = true;
    sub->handler = fn;
    box(sub->frame, 0, 0);
    if (!om->subopts) {
        om->subopts = list_init(NULL);
    }
    nodelay(sub->frame, TRUE);
    keypad(sub->frame, TRUE);
    list_push_back(om->subopts, sub);
    return sub;
}

int get_cols(menu_type type, char **opts, int num_opts)
{
    int cols = 0;

    for (int i = 0; i < num_opts; i++) {
        int len = strlen(opts[i]);

        if (cols < len) {
            cols = len;
        }
    }
    switch (type) {
    case MENU_SINGLE_SELECT:
    case MENU_MULTI_SELECT:
        return cols + 8;
    case MENU_NORMAL:
    default:
        return cols + 4;
    }
}

void main_menu_render(screen *s)
{
    main_menu *menu = (main_menu *) s;

    print_menu(menu->opt);
}

void print_menu(list_t *items)
{
    const node_t *n = list_begin(items);

    while (n) {
        option_menu *om = list_data(n);
        int y = 0;

        for (int i = 0; i < om->num_opts; i++) {
            switch (om->type) {
            case MENU_SINGLE_SELECT:
            case MENU_MULTI_SELECT:
                if (om->opts[i].selected) {
                    mvwprintw(om->content, y++, 1, selected_txt);
                } else {
                    mvwprintw(om->content, y++, 1, unselected_txt);
                }
                wprintw(om->content, om->opts[i].txt);
                break;
            case MENU_NORMAL:
            default:
                mvwprintw(om->content, y++, 1, om->opts[i].txt);
                break;
            }
        }
        if (om->subopts) {
            print_menu(om->subopts);
        }
        if (om->wheader) {
            printat(om->wheader, 0, 1, A_NORMAL, om->header);
            wbkgd(om->wheader, get_theme_colour(MENU_BACKGROUND));
        }
        n = list_next(n);
    }
}

void main_menu_refresh(screen *s)
{
    main_menu *menu = (main_menu *) s;
    option_menu *focused = list_data(menu->current);
    screen *prev = screen_stack_prev();

    wbkgd(menu->base.win, get_theme_colour(MENU_BACKGROUND));
    wbkgd(focused->frame, get_theme_colour(MENU_BACKGROUND));
    wbkgd(focused->content, get_theme_colour(MENU_BACKGROUND));
    if (menu->update) {
        main_menu_render(s);
        menu->update = false;
    }
    touchwin(prev->win);
    wnoutrefresh(prev->win);
    show_selectionbar(focused->content, focused->i);
    mvwchgat(focused->wheader, 0, 0, -1, A_NORMAL,
             PAIR_NUMBER(get_theme_colour(MENU_SELECTIONBAR)), NULL);
    werase(status);
    touchwin(status);
    touchwin(menu->base.win);
    touchwin(focused->wheader);
    touchwin(focused->frame);
    touchwin(focused->content);
    wnoutrefresh(status);
    wnoutrefresh(menu->base.win);
    wnoutrefresh(focused->wheader);
    wnoutrefresh(focused->frame);
    wnoutrefresh(focused->content);
    doupdate();
}

void main_menu_free(screen *s)
{
    main_menu *menu = (main_menu *) s;

    delwin(menu->base.win);
    list_free(menu->opt, free_option_menu);
    free(menu);
}

void free_option_menu(void *d)
{
    option_menu *om = (option_menu *) d;

    delwin(om->frame);
    delwin(om->content);
    if (om->wheader) {
        delwin(om->wheader);
    }
    if (om->subopts) {
        list_free(om->subopts, free_option_menu);
    }
    free(om->opts);
    free(om);
}

void main_menu_get_input(screen *s)
{
    int c;
    main_menu *menu = (main_menu *) s;
    option_menu *focused = list_data(menu->current);

    if (focused->subopts) {
        const node_t *n = list_ith(focused->subopts, focused->i);
        option_menu *sub = list_data(n);

        if (sub->focus) {
            focused = sub;
        }
    }
    c = wgetch(focused->frame);
    switch (c) {
    case KEY_ESC:
        if (focused->is_suboption) {
            focused->focus = false;
            main_menu_refresh(s);
            break;
        }
    case KEY_F(2):
    case KEY_F(10):
    case 'q':
        pop_screen(s);
        break;
    case KEY_DOWN:
        handle_selectionbar(focused, c);
        break;
    case KEY_UP:
        handle_selectionbar(focused, c);
        break;
    case KEY_LEFT:
        if (focused->is_suboption) {
            focused->focus = false;
            main_menu_refresh(s);
            break;
        }
        handle_new_focus(s, c);
        break;
    case KEY_RIGHT:
        if (!focused->is_suboption) {
            handle_new_focus(s, c);
        }
        break;
    case KEY_ENTER:
    case '\n':
        if (focused->subopts) {
            const node_t *n = list_ith(focused->subopts, focused->i);
            option_menu *sub = list_data(n);

            if (!sub->focus) {
                sub->focus = true;
                wbkgd(sub->frame, get_theme_colour(MENU_BACKGROUND));
                wbkgd(sub->content, get_theme_colour(MENU_BACKGROUND));
                show_selectionbar(sub->content, sub->i);
                wnoutrefresh(sub->content);
                wnoutrefresh(sub->frame);
                doupdate();
            }
        } else {
            if (focused->type == MENU_SINGLE_SELECT) {
                focused->opts[focused->previ].selected = false;
                focused->opts[focused->i].selected = true;
                focused->previ = focused->i;
                main_menu_render(s);
                show_selectionbar(focused->content, focused->i);
                wrefresh(focused->content);
            } else if (focused->type == MENU_MULTI_SELECT) {
                focused->opts[focused->i].selected = !focused->opts[focused->i].selected;
                main_menu_render(s);
                show_selectionbar(focused->content, focused->i);
                wrefresh(focused->content);
            }
            focused->handler(focused->i);
        }
        break;
    default:
        break;
    }
}

void handle_new_focus(screen *s, int c)
{
    main_menu *menu = (main_menu *) s;
    const node_t *n = (c == KEY_RIGHT) ? list_next(menu->current) :
        list_prev(menu->current);

    if (n) {
        menu->current = n;
        main_menu_refresh(s);
    }
}

void handle_selectionbar(option_menu *om, int c)
{
    switch (c) {
    case KEY_DOWN:
        remove_selectionbar(om->content, om->i);
        om->i = (om->i + 1) % om->num_opts;
        show_selectionbar(om->content, om->i);
        wrefresh(om->content);
        break;
    case KEY_UP:
        remove_selectionbar(om->content, om->i);
        om->i = (om->i == 0) ? (om->num_opts - 1) : (om->i - 1) % om->num_opts;
        show_selectionbar(om->content, om->i);
        wrefresh(om->content);
    default:
        break;
    }
}
