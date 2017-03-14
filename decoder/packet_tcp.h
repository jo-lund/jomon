#ifndef PACKET_TCP_H
#define PACKET_TCP_H

#include "packet.h"

/* TCP Option-Kind */
#define TCP_OPT_END 0       /* end of options list */
#define TCP_OPT_NOP 1       /* no operation - this may be used to align option fields on
                               32-bit boundaries */
#define TCP_OPT_MSS 2       /* maximum segment size */
#define TCP_OPT_WIN_SCALE 3 /* window scale */
#define TCP_OPT_SAP 4       /* selective acknowledgement permitted */
#define TCP_OPT_SACK 5      /* selective acknowledgement */
#define TCP_OPT_TIMESTAMP 8 /* timestamp and echo of previous timestamp */

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
    uint8_t option_kind;
    uint8_t option_length;
    union {
        uint8_t nop; /* count of nop padding bytes */
        uint16_t mss;
        uint8_t win_scale;
        bool sack_permitted; /* may be sent in a SYN by a TCP that has been extended to
                              * receive the SACK option once the connection has opened */
        list_t *sack;    /* list of sack blocks */
        uint32_t ts_val; /* timestamp value */
        uint32_t ts_ecr; /* timestamp echo reply */
    };
};

struct tcp_sack_block {
    uint32_t left_edge;
    uint32_t right_edge;
};

/*
 * Parses and returns the TCP options in the TCP header.
 * The list needs to be freed with 'free_tcp_options' after use.
 */
list_t *parse_tcp_options(unsigned char *data, int len);

void free_tcp_options(list_t *options);

/* should be internal to the decoder */
bool handle_tcp(unsigned char *buffer, int n, struct tcp *info);

#endif
