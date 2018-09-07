#ifndef HOST_SCREEN_H
#define HOST_SCREEN_H

#include "layout_int.h"
#include "../vector.h"

typedef struct {
    screen base;
    WINDOW *header;
    int top;
    int y;
    int lines;
    vector_t *screen_buf;
} host_screen;

host_screen *host_screen_create();
void host_screen_free(screen *s);

#endif
