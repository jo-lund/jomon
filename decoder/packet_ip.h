#ifndef PACKET_IP_H
#define PACKET_IP_H

#include "packet_icmp.h"
#include "packet_igmp.h"
#include "packet_tcp.h"
#include "packet_udp.h"
#include "packet_pim.h"

#define IP_PAYLOAD_LEN(p) ((p)->eth.ethertype == ETH_P_IP) ? \
    ((p)->eth.ip->length - (p)->eth.ip->ihl * 4) :          \
    ((p)->eth.ipv6->payload_len)

#define IPV6_FIXED_HEADER_LEN 40

// TODO: Improve the structure of this
struct ip_info {
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
    union {
        struct udp_info udp;
        struct tcp tcp;
        struct igmp_info igmp;
        struct icmp_info icmp;
        struct pim_info pim;
    };
};

struct ipv6_info {
    unsigned int version : 4;
    uint8_t tc;
    unsigned int flow_label : 20;
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
    union {
        struct udp_info udp;
        struct tcp tcp;
        struct igmp_info igmp;
        struct pim_info pim;
    };
};

char *get_ip_dscp(uint8_t dscp);
char *get_ip_transport_protocol(uint8_t protocol);

/* Return a pointer the IPv4/IPv6 payload */
unsigned char *get_ip_payload(struct packet *p);

struct packet_flags *get_ipv4_flags();

/* internal to the decoder */
bool handle_ipv4(unsigned char *buffer, int n, struct eth_info *info);
bool handle_ipv6(unsigned char *buffer, int n, struct eth_info *info);

#endif
