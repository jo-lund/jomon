#ifndef PACKET_SSDP_H
#define PACKET_SSDP_H

#include <stdbool.h>
#include <stdint.h>
#include "packet.h"

struct ssdp_info {
    list_t *fields;
};

/* internal to the decoder */
void register_ssdp(void);
packet_error handle_ssdp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata);

#endif
