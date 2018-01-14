#ifndef MAIN_MENU_H
#define MAIN_MENU_H

#include "layout_int.h"

typedef void (*menu_handler)(int i);

typedef struct main_menu {
    screen base;
    WINDOW *opt;
    WINDOW *header;
    int i;
    menu_handler handler;
    struct main_menu *next;
} main_menu;

main_menu *main_menu_create();
void main_menu_free(screen *s);

#endif
