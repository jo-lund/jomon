#ifndef PACKET_UDP_H
#define PACKET_UDP_H

#include "packet.h"

struct udp_info {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len; /* length of UDP header and data */
    uint16_t checksum;
    struct application_info data;
};

/* internal to the decoder */
bool handle_udp(unsigned char *buffer, int n, struct ip_info *info);

#endif
