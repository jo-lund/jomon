#ifndef PACKET_HTTP_H
#define PACKET_HTTP_H

#include <stdbool.h>
#include "rbtree.h"

struct http_info {
    char *start_line;
    rbtree_t *header;
    unsigned char *data;
    unsigned int len;
};

/* internal to the decoder */
void register_http(void);

#endif
