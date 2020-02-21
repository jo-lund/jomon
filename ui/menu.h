#ifndef MAIN_MENU_H
#define MAIN_MENU_H

#include "layout_int.h"
#include "../list.h"
#include "screen.h"

typedef enum option_menu_type {
    MENU_NORMAL,
    MENU_SINGLE_SELECT,
    MENU_MULTI_SELECT
} menu_type;

typedef void (*menu_handler)(int i);

typedef struct option_menu option_menu;

typedef struct main_menu {
    screen base;
    bool update;
    list_t *opt;
    const node_t *current;
} main_menu;

main_menu *main_menu_create();
option_menu *main_menu_add_options(main_menu *menu, menu_type type, char *header,
                                   char **opts, int num_opts, menu_handler fn);
option_menu *main_menu_add_suboptions(option_menu *om, menu_type type, int sub_idx,
                                      char **opts, int num_opts, menu_handler fn);
void main_menu_free(screen *s);

#endif
