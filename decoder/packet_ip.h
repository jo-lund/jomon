#ifndef PACKET_IP_H
#define PACKET_IP_H

#include "packet_icmp.h"
#include "packet_igmp.h"
#include "packet_tcp.h"
#include "packet_udp.h"
#include "packet_pim.h"

#define IPV6_FIXED_HEADER_LEN 40

struct ipv4_info {
    unsigned int version : 4;
    unsigned int ihl     : 4; /* Internet Header Length */
    unsigned int dscp    : 6; /* Differentiated Services Code Point (RFC 2474) */
    unsigned int ecn     : 2; /* Explicit congestion notification (RFC 3168) */
    uint16_t length; /* The entire packet size in bytes, including header and data */
    uint16_t id; /* Identification field, used for uniquely identifying group of fragments */
    uint16_t foffset; /* Fragment offset. The first 3 bits are flags.*/
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};

#define get_ipv4(p) ((struct ipv4_info *)(p)->root->next->data)
#define ipv4_src(p) get_ipv4(p)->src
#define ipv4_dst(p) get_ipv4(p)->dst
#define ipv4_protocol(p) get_ipv4(p)->protocol

struct ipv6_info {
    unsigned int version : 4;
    uint8_t tc;
    unsigned int flow_label : 20;
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
};

#define get_ipv6(p) ((struct ipv6_info *)(p)->root->next->data)
#define ipv6_src(p) get_ipv6(p)->src
#define ipv6_dst(p) get_ipv6(p)->dst
#define ipv6_protocol(p) get_ipv6(p)->next_header

char *get_ip_dscp(uint8_t dscp);
char *get_ip_transport_protocol(uint8_t protocol);

/* Get the IPv4 packet flags */
struct packet_flags *get_ipv4_flags();
int get_ipv4_flags_size();

/* Get the IPv4 fragment offset field */
uint16_t get_ipv4_foffset(struct ipv4_info *ip);

/* internal to the decoder */
void register_ip();
packet_error handle_ipv4(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata);
packet_error handle_ipv6(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata);

#endif
