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
        struct {
            uint32_t ts_val; /* timestamp value */
            uint32_t ts_ecr; /* timestamp echo reply */
        } ts;
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

struct packet_flags *get_tcp_flags();
int get_tcp_flags_size();

uint16_t get_tcp_src(const struct packet *p);
uint16_t get_tcp_dst(const struct packet *p);

/* should be internal to the decoder */
void register_tcp();
packet_error handle_tcp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata);

#endif
