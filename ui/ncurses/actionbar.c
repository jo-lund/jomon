#include <stdbool.h>
#include "actionbar.h"
#include "screen.h"
#include "hashmap.h"
#include "monitor.h"
#include "hash.h"
#include "signal.h"
#include "list.h"

#define STATUS_HEIGHT 1
#define ELEM_WIDTH 11

typedef struct elem {
    char *key;
    char *text;
    bool disabled;
} actionbar_elem;

static hashmap_t *screens;
list_t *defaults;

static void free_elem(void *p)
{
    list_free(p, free);
}

actionbar_t *actionbar_create(void)
{
    actionbar_t *bar;
    int my, mx;

    screens = hashmap_init(10, hashfnv_uint64, compare_uint);
    defaults = list_init(NULL);
    hashmap_set_free_data(screens, free_elem);
    bar = malloc(sizeof(*bar));
    getmaxyx(stdscr, my, mx);
    bar->base.win = newwin(STATUS_HEIGHT, mx, my - STATUS_HEIGHT, 0);
    bar->base.focus = false;
    bar->visible = true;
    return bar;
}

void actionbar_free(actionbar_t *bar)
{
    hashmap_free(screens);
    list_free(defaults, free);
    delwin(bar->base.win);
    free(bar);
}

void actionbar_refresh(actionbar_t *bar, screen *s)
{
    int colour = get_theme_colour(STATUS_BUTTON);
    int disabled = get_theme_colour(DISABLE);
    list_t *elems;
    const node_t *n;

    if (!bar->visible || !s->fullscreen)
        return;
    werase(bar->base.win);
    if (s->resize)
        mvwin(bar->base.win, getmaxy(stdscr) - STATUS_HEIGHT, 0);
    wbkgd(bar->base.win, get_theme_colour(BACKGROUND));
    if ((elems = hashmap_get(screens, s)) == NULL)
        elems = defaults;
    DLIST_FOREACH(elems, n) {
        actionbar_elem *elem = list_data(n);

        if (elem->disabled)
            printat(bar->base.win, disabled, "%s", elem->key);
        else
            wprintw(bar->base.win, "%s", elem->key);
        printat(bar->base.win, colour, "%-*s", ELEM_WIDTH, elem->text);
    }
    wrefresh(bar->base.win);
}

void actionbar_add(screen *s, char *key, char *text, bool disabled)
{
    list_t *elems;
    actionbar_elem *elem = malloc(sizeof(*elem));

    elem->key = key;
    elem->text = text;
    elem->disabled = disabled;
    if (hashmap_contains(screens, s)) {
        elems = hashmap_get(screens, s);
        list_push_back(elems, elem);
    } else {
        elems = list_init(NULL);
        list_push_back(elems, elem);
        hashmap_insert(screens, s, elems);
    }
}

void actionbar_update(screen *s, char *key, char *text, bool disabled)
{
    list_t *elems;
    const node_t *n;

    if (!hashmap_contains(screens, s))
        return;
    elems = hashmap_get(screens, s);
    DLIST_FOREACH(elems, n) {
        actionbar_elem *elem = list_data(n);

        if (strcmp(key, elem->key) == 0) {
            if (text)
                elem->text = text;
            elem->disabled = disabled;
            break;
        }
    }
    actionbar_refresh(actionbar, s);
}

void actionbar_add_default(char *key, char *text, bool disabled)
{
    actionbar_elem *elem = malloc(sizeof(*elem));

    elem->key = key;
    elem->text = text;
    elem->disabled = disabled;
    list_push_back(defaults, elem);
}

int actionbar_getmaxy(actionbar_t *bar)
{
    return getmaxy(bar->base.win);
}
