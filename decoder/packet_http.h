#ifndef PACKET_HTTP_H
#define PACKET_HTTP_H

#include <stdbool.h>
#include "../rbtree.h"

struct http_info {
    char *start_line;
    rbtree_t *header;
    unsigned char *data;
    unsigned int len;
};

struct application_info;

/* internal to the decoder */
void register_http();
packet_error handle_http(struct protocol_info *pinfo, unsigned char *buffer,
                         int len, struct application_info *info);

#endif
