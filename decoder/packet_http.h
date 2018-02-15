#ifndef PACKET_HTTP_H
#define PACKET_HTTP_H

#include <stdbool.h>

struct http_info {
    char *start_line;
    list_t *header;
    unsigned char *data;
    unsigned int len;
};

struct application_info;

/* internal to the decoder */
packet_error handle_http(unsigned char *buffer, uint16_t len, struct application_info *info);
void free_http_packet(struct http_info *http);

#endif
