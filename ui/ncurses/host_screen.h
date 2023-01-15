#ifndef HOST_SCREEN_H
#define HOST_SCREEN_H

#include "layout.h"
#include "screen.h"
#include "vector.h"

typedef struct {
    screen base;
    WINDOW *header;
    int y;
    vector_t *screen_buf;
} host_screen;

host_screen *host_screen_create(void);
void host_screen_free(screen *s);

#endif
