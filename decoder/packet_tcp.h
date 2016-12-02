#ifndef PACKET_TCP_H
#define PACKET_TCP_H

#include "packet.h"

#define TCP_PAYLOAD_LEN(p) ((p)->eth.ethertype == ETH_P_IP) ?           \
    ((p)->eth.ip->length - (p)->eth.ip->ihl * 4 - (p)->eth.ip->tcp.offset * 4) : \
    ((p)->eth.ipv6->payload_len - (p)->eth.ipv6->tcp.offset * 4)

struct tcp {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    unsigned int offset : 4;
    unsigned int ns  : 1;
    unsigned int cwr : 1;
    unsigned int ece : 1;
    unsigned int urg : 1;
    unsigned int ack : 1;
    unsigned int psh : 1;
    unsigned int rst : 1;
    unsigned int syn : 1;
    unsigned int fin : 1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
    unsigned char *options;
    struct application_info data;
};

struct tcp_options {
    uint8_t nop; /* count of nop padding bytes */
    uint16_t mss;
    uint8_t win_scale;
    bool sack_permitted; /* may be sent in a SYN by a TCP that has been extended to
                          * receive the SACK option once the connection has opened */
    list_t *sack;    /* list of sack blocks */
    uint32_t ts_val; /* timestamp value */
    uint32_t ts_ecr; /* timestamp echo reply */
};

struct tcp_sack_block {
    uint32_t left_edge;
    uint32_t right_edge;
};

bool handle_tcp(unsigned char *buffer, int n, struct tcp *info);

/*
 * Parses and returns the TCP options in the TCP header.
 * This needs to be freed by calling free_tcp_options.
 */
struct tcp_options *parse_tcp_options(unsigned char *data, int len);

/* Frees the tcp_options struct that was allocated by parse_tcp_options */
void free_tcp_options(struct tcp_options *options);

#endif
