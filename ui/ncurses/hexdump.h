#ifndef HEXDUMP_H
#define HEXDUMP_H

#include "list_view.h"

enum hexmode {
    HEXMODE_NORMAL,
    HEXMODE_WIDE
};

#define HEXMODES 2

struct packet;

void add_hexdump(list_view *lw, list_view_header *header, enum hexmode mode,
                 unsigned char *payload, uint16_t len);
void add_winhexdump(WINDOW *win, int y, int x, enum hexmode mode, struct packet *p);

#endif
