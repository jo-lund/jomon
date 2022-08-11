#ifndef PACKET_IP_H
#define PACKET_IP_H

#include "packet_icmp.h"
#include "packet_igmp.h"
#include "packet_tcp.h"
#include "packet_udp.h"
#include "packet_pim.h"

#define IP_OPT_END 0
#define IP_OPT_NOP 1
#define IP_OPT_SECURITY 2
#define IP_OPT_LSR 3  /* loose source routing */
#define IP_OPT_TIMESTAMP 4
#define IP_OPT_RR 7   /* record route */
#define IP_OPT_STREAM_ID 8
#define IP_OPT_SSR 9  /* strict source routing */
#define IP_OPT_ROUTER_ALERT 20
#define GET_IP_OPTION_NUMBER(t) ((t) & 0x1f)

#define IP_UNCLASSIFIED 0
#define IP_CONFIDENTIAL 0xf135
#define IP_EFTO  0x789a
#define IP_MMMM 0xbc4d
#define IP_PROG 0x5e26
#define IP_SECRET 0xd788
#define IP_TOP_SECRET 0x6bc5

#define IP_TS_ONLY 0
#define IP_TS_ADDR 1
#define IP_TS_PRESPECIFIED 3
#define IP_STANDARD_TS(ts) (((ts) & 0x80000000) == 0)

struct ipv4_options {
    uint8_t type;
    uint8_t length;
    struct {
        uint16_t security;
        uint16_t compartments;
        uint16_t restrictions;
        unsigned int tcc : 24;
    } security;
    struct {
        uint8_t pointer;
        uint32_t *route_data;
    } route;
    uint16_t stream_id;
    uint16_t router_alert;
    struct {
        uint8_t pointer;
        uint8_t oflw : 4;
        uint8_t flg : 4;
        struct {
            uint32_t *addr;
            uint32_t *timestamp;
        } *ts;
    } timestamp;
    struct ipv4_options *next;
};

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
    uint32_t src; /* stored in network byte order */
    uint32_t dst; /* stored in network byte order */
    struct ipv4_options *opt;
};

#define get_ipv4(p) ((struct ipv4_info *)(p)->root->next->data)
#define ipv4_src(p) get_ipv4(p)->src
#define ipv4_dst(p) get_ipv4(p)->dst
#define ipv4_protocol(p) get_ipv4(p)->protocol

/* Get the string representation of the IPv4/IPv6 transport protocol */
char *get_ip_transport_protocol(uint8_t protocol);

/*
 * Get the string representation of the IPv4 Differentiated Services Code Point
 * class selector
*/
char *get_ipv4_dscp(uint8_t dscp);

/* Get the IPv4 packet flags */
struct packet_flags *get_ipv4_flags(void);
int get_ipv4_flags_size(void);

/* Get the IPv4 option type packet flags */
struct packet_flags *get_ipv4_opt_flags(void);
int get_ipv4_opt_flags_size(void);

/* Get the IPv4 fragment offset field */
uint16_t get_ipv4_foffset(struct ipv4_info *ip);

/* Get the string representation of the options fields */
char *get_ipv4_security(uint16_t security);

/* Get the string representation of the option's type */
char *get_ipv4_opt_type(uint8_t type);

/* Get the string representation of the router alert option value */
char *get_router_alert_option(uint16_t opt);

/* internal to the decoder */
void register_ip(void);

/*
 * Parse 'count' number of ip addresses from buffer and store them in 'addrs'.
 * Return the new length of buffer.
 */
int parse_ipv4_addr(uint32_t *addrs, int count, unsigned char **buf, int n);

#endif
