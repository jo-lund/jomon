#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "packet_ip.h"
#include "../error.h"
#include "../util.h"

/*
 * IP Differentiated Services Code Point class selectors.
 * Prior to DiffServ, IPv4 networks could use the Precedence field in the TOS
 * byte of the IPv4 header to mark priority traffic. In order to maintain
 * backward compatibility with network devices that still use the Precedence
 * field, DiffServ defines the Class Selector PHB.
 *
 * The Class Selector code points are of the form 'xxx000'. The first three bits
 * are the IP precedence bits. Each IP precedence value can be mapped into a
 * DiffServ class. CS0 equals IP precedence 0, CS1 IP precedence 1, and so on.
 * If a packet is received from a non-DiffServ aware router that used IP
 * precedence markings, the DiffServ router can still understand the encoding as
 * a Class Selector code point.
 */
#define CS0 0X0
#define CS1 0X8
#define CS2 0X10
#define CS3 0X18
#define CS4 0X20
#define CS5 0X28
#define CS6 0X30
#define CS7 0X38

extern void add_ipv4_information(void *w, void *sw, void *data);
extern void print_ipv4(char *buf, int n, void *data);
extern void add_ipv6_information(void *w, void *sw, void *data);
extern void print_ipv6(char *buf, int n, void *data);

static struct packet_flags ipv4_flags[] = {
    { "Reserved", 1, NULL },
    { "Don't Fragment", 1, NULL },
    { "More Fragments", 1, NULL }
};

static struct protocol_info ipv4_prot = {
    .short_name = "IPv4",
    .long_name = "Internet Protocol Version 4",
    .decode = handle_ipv4,
    .print_pdu = print_ipv4,
    .add_pdu = add_ipv4_information
};

static struct protocol_info ipv6_prot = {
    .short_name = "IPv6",
    .long_name = "Internet Protocol Version 6",
    .decode = handle_ipv6,
    .print_pdu = print_ipv6,
    .add_pdu = add_ipv6_information
};

void register_ip(void)
{
    register_protocol(&ipv4_prot, ETHERNET_II, ETHERTYPE_IP);
    register_protocol(&ipv6_prot, ETHERNET_II, ETHERTYPE_IPV6);
}

/*
 * IPv4 header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * IHL: Internet header length, the number of 32 bit words in the header.
 *      The minimum value for this field is 5: 5 * 32 = 160 bits (20 bytes).
 * Flags: Used to control and identify fragments
 *        Bit 0: Reserved, must be zero
 *        Bit 1: Don't Fragment (DF)
 *        Bit 2: More Fragments (MF)
 * Fragment offset: Specifies the offset of a particular fragment relative to
 * the beginning of the unfragmented IP datagram. The first fragment has an
 * offset of zero.
 * Protocol: Defines the protocol used in the data portion of the packet.
 */
packet_error handle_ipv4(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    struct ip *ip;
    unsigned int header_len;
    struct ipv4_info *ipv4;
    uint32_t id;

    ip = (struct ip *) buffer;
    if (n < ip->ip_hl * 4 || ip->ip_hl < 5) return DECODE_ERR;

    pinfo->num_packets++;
    pinfo->num_bytes += n;
    ipv4 = mempool_alloc(sizeof(struct ipv4_info));
    pdata->data = ipv4;
    ipv4->src = ip->ip_src.s_addr;
    ipv4->dst = ip->ip_dst.s_addr;
    ipv4->version = ip->ip_v;
    ipv4->ihl = ip->ip_hl;
    header_len = ip->ip_hl * 4;
    pdata->len = header_len;

    /* Originally defined as type of service, but now defined as differentiated
       services code point and explicit congestion control */
    ipv4->dscp = (ip->ip_tos & 0xfc) >> 2;
    ipv4->ecn = ip->ip_tos & 0x03;

    ipv4->length = ntohs(ip->ip_len);
    if (ipv4->length < header_len || /* total length less than header length */
        ipv4->length > n) { /* total length greater than packet length */
        return DECODE_ERR;
    }

    /* The packet has been padded in order to contain the minimum number of by
       bytes. The padded bytes should be ignored. */
    if (n > ipv4->length) {
        n = ipv4->length;
    }

    ipv4->id = ntohs(ip->ip_id);
    ipv4->foffset = ntohs(ip->ip_off);
    ipv4->ttl = ip->ip_ttl;
    ipv4->protocol = ip->ip_p;
    ipv4->checksum = ntohs(ip->ip_sum);
    id = get_protocol_id(IP_PROTOCOL, ipv4->protocol);

    struct protocol_info *layer3 = get_protocol(id);
    if (layer3) {
        pdata->next = mempool_alloc(sizeof(struct packet_data));
        memset(pdata->next, 0, sizeof(struct packet_data));
        pdata->next->prev = pdata;
        pdata->next->id = id;
        return layer3->decode(layer3, buffer + header_len, n - header_len, pdata->next);
    }
     return NO_ERR;
}

/*
 * IPv6 header
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version| Traffic Class |           Flow Label                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Payload Length        |  Next Header  |   Hop Limit   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                         Source Address                        +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                      Destination Address                      +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Version:             4-bit Internet Protocol version number = 6
 * Traffic Class:       8-bit traffic class field
 * Flow Label:          20-bit flow label
 * Payload Length:      16-bit unsigned integer. Length of the IPv6 payload,
                        i.e., the rest of the packet following this IPv6 header,
                        in octets.
 * Next Header:         8-bit selector. Identifies the type of header
 *                      immediately following the IPv6 header.
 * Hop Limit:           8-bit unsigned integer. Decremented by 1 by each node
                        that forwards the packet. The packet is discarded if Hop
                        Limit is decremented to zero.
 * Source Address:      128-bit address of the originator of the packet
 * Destination Address: 128-bit address of the intended recipient of the packet
 */
packet_error handle_ipv6(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    struct ip6_hdr *ip6;
    unsigned int header_len;
    struct ipv6_info *ipv6;
    uint32_t id;

    header_len = sizeof(struct ip6_hdr);
    if ((unsigned int) n < header_len)
        return DECODE_ERR;

    pinfo->num_packets++;
    pinfo->num_bytes += n;
    ip6 = (struct ip6_hdr *) buffer;
    ipv6 = mempool_alloc(sizeof(struct ipv6_info));
    pdata->data = ipv6;
    pdata->len = header_len;
    ipv6->version = ip6->ip6_vfc >> 4;
    ipv6->tc = ip6->ip6_vfc & 0x0f;
    ipv6->flow_label = ntohl(ip6->ip6_flow);
    ipv6->payload_len = ntohs(ip6->ip6_plen);
    ipv6->next_header = ip6->ip6_nxt;
    ipv6->hop_limit = ip6->ip6_hlim;
    memcpy(ipv6->src, ip6->ip6_src.s6_addr, 16);
    memcpy(ipv6->dst, ip6->ip6_dst.s6_addr, 16);
    id = get_protocol_id(IP_PROTOCOL, ipv6->next_header);

    // TODO: Handle IPv6 extension headers and errors
    struct protocol_info *layer3 = get_protocol(id);
    if (layer3) {
        pdata->next = mempool_alloc(sizeof(struct packet_data));
        memset(pdata->next, 0, sizeof(struct packet_data));
        pdata->next->prev = pdata;
        pdata->next->id = id;
        return layer3->decode(layer3, buffer + header_len, n - header_len, pdata->next);
    }
    return NO_ERR;
}

char *get_ip_dscp(uint8_t dscp)
{
    switch (dscp) {
    case CS0:
        return "Default";
    case CS1:
        return "Class Selector 1";
    case CS2:
        return "Class Selector 2";
    case CS3:
        return "Class Selector 3";
    case CS4:
        return "Class Selector 4";
    case CS5:
        return "Class Selector 5";
    case CS6:
        return "Class Selector 6";
    default:
        return NULL;
    }
}

char *get_ip_transport_protocol(uint8_t protocol)
{
    switch (protocol) {
    case IPPROTO_ICMP:
        return "ICMP";
    case IPPROTO_IGMP:
        return "IGMP";
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_PIM:
        return "PIM";
    default:
        return NULL;
    }
}

struct packet_flags *get_ipv4_flags(void)
{
    return ipv4_flags;
}

int get_ipv4_flags_size(void)
{
    return ARRAY_SIZE(ipv4_flags);
}

uint16_t get_ipv4_foffset(struct ipv4_info *ip)
{
    return ip->foffset & 0x1fff;
}
