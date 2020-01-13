#ifndef PACKET_UDP_H
#define PACKET_UDP_H

#include "packet.h"

#define UDP_HDR_LEN 8

struct udp_info {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len; /* length of UDP header and data */
    uint16_t checksum;
};

/* internal to the decoder */
void register_udp();
packet_error handle_udp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata);

#endif
