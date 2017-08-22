#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "packet_ip.h"
#include "../error.h"

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

static struct packet_flags ipv4_flags[] = {
    { "Reserved", 1, NULL },
    { "Don't Fragment", 1, NULL },
    { "More Fragments", 1, NULL }
};

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
packet_error handle_ipv4(unsigned char *buffer, int n, struct eth_info *eth)
{
    struct iphdr *ip;
    unsigned int header_len;

    ip = (struct iphdr *) buffer;
    if (n < ip->ihl * 4) return IPv4_ERR;

    pstat[PROT_IPv4].num_packets++;
    pstat[PROT_IPv4].num_bytes += n;
    eth->ip = calloc(1, sizeof(struct ipv4_info));
    eth->ip->src = ip->saddr;
    eth->ip->dst = ip->daddr;
    eth->ip->version = ip->version;
    eth->ip->ihl = ip->ihl;

    /* Originally defined as type of service, but now defined as differentiated
       services code point and explicit congestion control */
    eth->ip->dscp = (ip->tos & 0xfc) >> 2;
    eth->ip->ecn = ip->tos & 0x03;

    eth->ip->length = ntohs(ip->tot_len);
    eth->ip->id = ntohs(ip->id);
    eth->ip->foffset = ntohs(ip->frag_off);
    eth->ip->ttl = ip->ttl;
    eth->ip->protocol = ip->protocol;
    eth->ip->checksum = ntohs(ip->check);
    header_len = ip->ihl * 4;
    switch (ip->protocol) {
    case IPPROTO_ICMP:
        return handle_icmp(buffer + header_len, n - header_len, &eth->ip->icmp);
    case IPPROTO_IGMP:
        return handle_igmp(buffer + header_len, n - header_len, &eth->ip->igmp);
    case IPPROTO_TCP:
        return handle_tcp(buffer + header_len, n - header_len, &eth->ip->tcp);
    case IPPROTO_UDP:
        return handle_udp(buffer + header_len, n - header_len, &eth->ip->udp);
    case IPPROTO_PIM:
        return handle_pim(buffer + header_len, n - header_len, &eth->ip->pim);
    default:
        return NO_ERR;
    }
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
packet_error handle_ipv6(unsigned char *buffer, int n, struct eth_info *eth)
{
    struct ip6_hdr *ip6;
    unsigned int header_len;

    header_len = sizeof(struct ip6_hdr);
    if (n < header_len) return IPv6_ERR;

    pstat[PROT_IPv6].num_packets++;
    pstat[PROT_IPv6].num_bytes += n;
    ip6 = (struct ip6_hdr *) buffer;
    eth->ipv6 = calloc(1, sizeof(struct ipv6_info));
    eth->ipv6->version = ip6->ip6_vfc >> 4;
    eth->ipv6->tc = ip6->ip6_vfc & 0x0f;
    eth->ipv6->flow_label = ntohl(ip6->ip6_flow);
    eth->ipv6->payload_len = ntohs(ip6->ip6_plen);
    eth->ipv6->next_header = ip6->ip6_nxt;
    eth->ipv6->hop_limit = ip6->ip6_hlim;
    memcpy(eth->ipv6->src, ip6->ip6_src.s6_addr, 16);
    memcpy(eth->ipv6->dst, ip6->ip6_dst.s6_addr, 16);

    // TODO: Handle IPv6 extension headers and errors
    switch (eth->ipv6->next_header) {
    case IPPROTO_IGMP:
        return handle_igmp(buffer + header_len, n - header_len, &eth->ipv6->igmp);
    case IPPROTO_TCP:
        return handle_tcp(buffer + header_len, n - header_len, &eth->ipv6->tcp);
    case IPPROTO_UDP:
        return handle_udp(buffer + header_len, n - header_len, &eth->ipv6->udp);
    case IPPROTO_PIM:
        return handle_pim(buffer + header_len, n - header_len, &eth->ipv6->pim);
    case IPPROTO_ICMPV6:
    default:
        break;
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

unsigned char *get_ip_payload(struct packet *p)
{
    if (p->eth.ethertype == ETH_P_IP) {
        return p->eth.data + ETH_HLEN + p->eth.ip->ihl * 4;
    }
    if (p->eth.ethertype == ETH_P_IPV6) {
        return p->eth.data + ETH_HLEN + sizeof(struct ip6_hdr);
    }
    return NULL;
}

struct packet_flags *get_ipv4_flags()
{
    return ipv4_flags;
}

int get_ipv4_flags_size()
{
    return sizeof(ipv4_flags) / sizeof(struct packet_flags);
}

uint16_t get_ipv4_foffset(struct ipv4_info *ip)
{
    return ip->foffset & 0x1fff;
}
