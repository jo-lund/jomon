#ifndef PACKET_UDP_H
#define PACKET_UDP_H

#include "packet.h"

#define UDP_HDR_LEN 8

#define UDP_PAYLOAD_LEN(p) ((p)->eth.ethertype == ETH_P_IP) ?           \
    ((p)->eth.ipv4->udp->len - UDP_HDR_LEN) : ((p)->eth.ipv6->udp->len - UDP_HDR_LEN)

struct udp_info {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len; /* length of UDP header and data */
    uint16_t checksum;
    struct application_info data;
};

#define get_udp(p, v) ((p)->eth.ip##v->udp)
#define udp_src(p, v) get_udp(p, v)->src_port
#define udp_dst(p, v) get_udp(p, v)->dst_port
#define udp_data(p, v) get_udp(p, v)->data

/* internal to the decoder */
void register_udp();
packet_error handle_udp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        void *data);

#endif
