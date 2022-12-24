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
#define TCP_OPT_TFO 34      /* TCP Fast Open (RFC 7413) */

#define tcp_member(packet, member) ({ \
    struct packet_data *pdata = get_packet_data(packet, get_protocol_id(IP_PROTOCOL, IPPROTO_TCP)); \
    pdata->data ? ((struct tcp *) pdata->data)->member : 0;})

struct tcp {
    uint16_t sport;
    uint16_t dport;
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
    struct tcp_options *opt;
};

struct tcp_options {
    uint8_t option_kind;
    uint8_t option_length; /* length of value + 1 byte tag and 1 byte length */
    union {
        uint8_t nop; /* count of nop padding bytes */
        uint16_t mss;
        uint8_t win_scale;
        bool sack_permitted; /* may be sent in a SYN by a TCP that has been extended to
                              * receive the SACK option once the connection has opened */
        list_t *sack;    /* list of sack blocks */
        struct {
            uint32_t ts_val; /* timestamp value */
            uint32_t ts_ecr; /* timestamp echo reply */
        } ts;
        unsigned char *cookie;
    };
    struct tcp_options *next;
};

struct tcp_sack_block {
    uint32_t left_edge;
    uint32_t right_edge;
};

struct packet_flags *get_tcp_flags(void);
int get_tcp_flags_size(void);

/* should be internal to the decoder */
void register_tcp(void);
packet_error handle_tcp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata);

#endif
