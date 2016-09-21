#ifndef PACKET_HTTP_H
#define PACKET_HTTP_H

#include <stdbool.h>

struct http_info {
    char *start_line;
    list_t *header;
    char *data;
    unsigned int len;
};

struct application_info;

bool handle_http(unsigned char *buffer, struct application_info *info, uint16_t len);

#endif
