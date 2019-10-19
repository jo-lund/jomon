#ifndef PACKET_IGMP_H
#define PACKET_IGMP_H

#include <stdbool.h>
#include <netinet/in.h>
#include "packet.h"

struct igmp_info {
    uint8_t type;
    uint8_t max_resp_time;
    uint16_t checksum;
    uint32_t group_addr;
};

#define get_igmp(p, v) ((p)->eth.ip##v->igmp)

struct ipv4_info;

void register_igmp();
packet_error handle_igmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         void *data);
char *get_igmp_type(uint8_t type);

#endif
