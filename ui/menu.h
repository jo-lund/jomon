#ifndef MAIN_MENU_H
#define MAIN_MENU_H

#include "layout_int.h"
#include "../list.h"

typedef void (*menu_handler)(int i);

typedef struct main_menu {
    screen base;
    bool update;
    list_t *opt;
    const node_t *cur;
} main_menu;

main_menu *main_menu_create();
void main_menu_add_options(main_menu *menu, char *header, char **opts,
                           int num_opts, menu_handler fn);
void main_menu_free(screen *s);

#endif
