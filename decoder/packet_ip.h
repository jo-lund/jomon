#ifndef PACKET_IP_H
#define PACKET_IP_H

#include "packet_icmp.h"
#include "packet_igmp.h"
#include "packet_tcp.h"
#include "packet_udp.h"

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
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    uint16_t payload_len; /* length of payload if transport protocol is unknown */
    union {
        struct udp_info udp;
        struct tcp tcp;
        struct igmp_info igmp;
        struct icmp_info icmp;
        unsigned char *payload;
    };
};

bool handle_ip(unsigned char *buffer, int n, struct eth_info *info);
char *get_ip_dscp(uint8_t dscp);
char *get_ip_transport_protocol(uint8_t protocol);

#endif
