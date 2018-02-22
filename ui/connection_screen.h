#ifndef CONNECTION_SCREEN_H
#define CONNECTION_SCREEN_H

#include "layout_int.h"
#include "../vector.h"

typedef struct {
    screen base;
    WINDOW *header;
    int top;
    int y;
    int lines;
    vector_t *screen_buf;
} connection_screen;

connection_screen *connection_screen_create();
void connection_screen_free(screen *s);

#endif
