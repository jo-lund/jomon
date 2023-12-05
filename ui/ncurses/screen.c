#define _GNU_SOURCE
#include <stdlib.h>
#include "screen.h"
#include "layout.h"
#include "menu.h"
#include "dialogue.h"
#include "misc.h"
#include "util.h"

extern main_menu *menu;
extern vector_t *packets;

static void handle_keydown(screen *s)
{
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
        SCREEN_REFRESH(s);
    } else {
        if (s->top > 0) {
            s->top--;
            SCREEN_REFRESH(s);
        }
    }
}

static void scroll_page(screen *s, int num_lines)
{
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

static void handle_end(screen *s, int my)
{
    unsigned int size;

    size = SCREEN_GET_DATA_SIZE(s);
    if (size >= (unsigned int) my)
        s->top = size - my;
    if (s->show_selectionbar)
        s->selectionbar = size - 1;
    SCREEN_REFRESH(s);
}

static void handle_header_focus(screen *s, int key)
{
    switch (key) {
    case KEY_RIGHT:
        s->hpos = (s->hpos + 1) % s->header_size;
        break;
    case KEY_LEFT:
        if (s->hpos == 0)
            s->hpos = s->header_size - 1;
        else
            s->hpos = (s->hpos - 1) % s->header_size;
        break;
    default:
        break;
    }
    SCREEN_REFRESH(s);
}

static void handle_warning(void *arg)
{
    jomon_exit(PTR_TO_UINT(arg));
}

screen *screen_create(screen_operations *defop)
{
    screen *s;

    s = xmalloc(sizeof(screen));
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
    s->header = NULL;
    s->hpos = 0;
    s->tab_active = false;
    s->header_size = 0;
    s->hide_selectionbar = false;
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
        if (s->header && s->tab_active) {
            s->tab_active = false;
            if (s->hide_selectionbar)
                s->hide_selectionbar = false;
        }
        if (s->have_selectionbar && SCREEN_GET_DATA_SIZE(s) > 0) {
            s->show_selectionbar = !s->show_selectionbar;
            s->selectionbar = s->top;
            SCREEN_REFRESH(s);
        }
        break;
    case 'n':
        ctx.opt.numeric = !ctx.opt.numeric;
        SCREEN_REFRESH(s);
        break;
    case 'p':
        if (s->num_pages > 0) {
            s->top = 0;
            s->page = (s->page + 1) % s->num_pages;
            SCREEN_REFRESH(s);
        }
        break;
    case 's':
        screen_stack_move_to_top(screen_cache_get(STAT_SCREEN));
        break;
    case KEY_ESC:
        if (s->tab_active) {
            s->tab_active = false;
            if (s->hide_selectionbar) {
                s->show_selectionbar = true;
                s->hide_selectionbar = false;
            }
            SCREEN_REFRESH(s);
            break;
        } else if (s->show_selectionbar) {
            s->show_selectionbar = false;
            SCREEN_REFRESH(s);
            break;
        }
        FALLTHROUGH;
    case 'x':
    case KEY_F(3):
        if (screen_stack_size() > 1) {
            if (s->op->screen_on_back)
                SCREEN_ON_BACK(s);
            pop_screen();
        }
        break;
    case '?':
    case KEY_F(1):
        screen_stack_move_to_top(screen_cache_get(HELP_SCREEN));
        break;
    case KEY_F(2):
        push_screen((screen *) menu);
        break;
    case KEY_F(10):
    case 'q':
        if (vector_size(packets) > 0 && !ctx.pcap_saved)
            create_warning_dialogue("Packet capture not saved. Do you really want to quit?",
                                    handle_warning, UINT_TO_PTR(0), NULL, NULL);
        else
            jomon_exit(0);
        break;
    case KEY_UP:
        handle_keyup(s);
        break;
    case KEY_DOWN:
        if (s->op->screen_get_data_size)
            handle_keydown(s);
        break;
    case ' ':
    case KEY_NPAGE:
        if (s->op->screen_get_data_size)
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
        if (s->op->screen_get_data_size)
            handle_end(s, my);
        break;
    case '\t':
        if (!s->header)
            return;
        if (!s->tab_active) {
            s->tab_active = true;
            s->hpos = 0;
            if (s->show_selectionbar) {
                s->hide_selectionbar = true;
                s->show_selectionbar = false;
            }
            SCREEN_REFRESH(s);
        } else {
            handle_header_focus(s, KEY_RIGHT);
        }
        break;
    case KEY_LEFT:
        if (s->header && s->tab_active)
            handle_header_focus(s, KEY_LEFT);
        break;
    case KEY_RIGHT:
        if (s->header && s->tab_active)
            handle_header_focus(s, KEY_RIGHT);
        break;
    default:
        break;
    }
}

void screen_render_header_focus(screen *s, WINDOW *whdr)
{
    int x;

    mvwchgat(whdr, HEADER_HEIGHT - 1, 0, -1, A_NORMAL, PAIR_NUMBER(get_theme_colour(HEADER)), NULL);
    if ((unsigned int ) s->hpos >= s->header_size)
        s->hpos = s->header_size - 1;
    x = 0;
    for (unsigned int i = 0; i < s->header_size; i++) {
        switch (s->header[i].order) {
        case HDR_INCREASING:
            mvprintat(whdr, HEADER_HEIGHT - 1, x + s->header[i].width - 2, get_theme_colour(HEADER), "+");
            break;
        case HDR_DECREASING:
            mvprintat(whdr, HEADER_HEIGHT -1, x + s->header[i].width - 2, get_theme_colour(HEADER), "-");
            break;
        default:
            break;
        }
        x += s->header[i].width;
    }
    if (s->tab_active) {
        unsigned int i = 0;

        x = 0;
        while (i < s->hpos)
            x += s->header[i++].width;
        mvwchgat(whdr, HEADER_HEIGHT -1, x, s->header[i].width, A_NORMAL,
                 PAIR_NUMBER(get_theme_colour(FOCUS)), NULL);
    }
}

void screen_update_order(screen *s, void *data, int size,
                         int (*cmp_elem)(const void *, const void *, void *))
{
    for (unsigned int i = 0; i < s->header_size; i++) {
        if (i != s->hpos)
            s->header[i].order = -1;
    }
    s->header[s->hpos].order = (s->header[s->hpos].order + 1) % 2;
    qsort_r(data, size, sizeof(void *), cmp_elem, INT_TO_PTR(s->hpos));
}

int screen_get_active_header_focus(screen *s)
{
    for (unsigned int i = 0; i < s->header_size; i++)
        if (s->header[i].order != -1)
            return i;
    return -1;
}
