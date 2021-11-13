#ifndef UI_PROTOCOLS_H
#define UI_PROTOCOLS_H

#include "list_view.h"

#define ADDR_WIDTH 40
#define PROT_WIDTH 10
#define NUM_WIDTH 10
#define TIME_WIDTH 20

/* write packet to buffer */
void write_to_buf(char *buf, int size, struct packet *p);

#endif
