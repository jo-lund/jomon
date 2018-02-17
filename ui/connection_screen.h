#ifndef CONNECTION_SCREEN_H
#define CONNECTION_SCREEN_H

#include "layout_int.h"
#include "../list.h"
#include "../hashmap.h"

typedef struct {
    screen base;
    WINDOW *header;
    int top;
    int y;
    int lines;
    list_t *screen_buf;
    hash_map_t *sessions;
} connection_screen;

connection_screen *connection_screen_create();
void connection_screen_free(screen *s);

#endif
