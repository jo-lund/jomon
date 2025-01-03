#include <sys/types.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include "packet_ip6.h"
#include "packet.h"
#include "util.h"

extern void add_ipv6_information(void *w, void *sw, void *data);
extern void print_ipv6(char *buf, int n, void *data);
static packet_error handle_ipv6(struct protocol_info *pinfo, unsigned char *buffer, int n,
                                struct packet_data *pdata);

static struct protocol_info ipv6_prot = {
    .short_name = "IPv6",
    .long_name = "Internet Protocol Version 6",
    .decode = handle_ipv6,
    .print_pdu = print_ipv6,
    .add_pdu = add_ipv6_information
};

void register_ip6(void)
{
    register_protocol(&ipv6_prot, ETHERNET_II, ETHERTYPE_IPV6);
    register_protocol(&ipv6_prot, PKT_LOOP, ETHERTYPE_IPV6);
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
    unsigned int header_len;
    struct ipv6_info *ipv6;
    uint32_t id;

    ipv6 = mempool_alloc(sizeof(struct ipv6_info));
    pdata->data = ipv6;
    header_len = sizeof(struct ip6_hdr);
    if ((unsigned int) n < header_len) {
        memset(ipv6, 0, sizeof(*ipv6));
        pdata->len = n;
        pdata->error = create_error_string("Packet length (%d) less than IP6 header length (%d)",
                                           n, header_len);
        return DECODE_ERR;
    }
    pdata->len = header_len;
    ipv6->version = buffer[0] >> 4;
    if (ipv6->version != 6)
        pdata->error = create_error_string("IP6 version error %d != 6", ipv6->version);
    ipv6->tc = (buffer[0] & 0x0f) << 4 | (buffer[1] & 0xf0) >> 4;
    ipv6->flow_label = (buffer[1] & 0x0f) << 16 | buffer[2] << 8 | buffer[3];
    buffer += 4;
    ipv6->payload_len = read_uint16be(&buffer);
    ipv6->next_header = *buffer++;
    ipv6->hop_limit = *buffer++;
    memcpy(ipv6->src, buffer, 16);
    memcpy(ipv6->dst, buffer + 16, 16);
    buffer += 32;
    id = get_protocol_id(IP6_PROT, ipv6->next_header);
    pinfo->num_packets++;
    pinfo->num_bytes += n;

    // TODO: Handle IPv6 extension headers and errors
    struct protocol_info *layer3 = get_protocol(id);
    if (layer3) {
        pdata->next = mempool_calloc(1, struct packet_data);
        pdata->next->prev = pdata;
        pdata->next->id = id;
        if (layer3->decode(layer3, buffer, n - header_len, pdata->next) == UNK_PROTOCOL) {
            mempool_free(pdata->next);
            pdata->next = NULL;
        }
    }
    return NO_ERR;
}

int parse_ipv6_addr(uint8_t *addrs, int count, unsigned char **buf, int n)
{
    unsigned char *p = *buf;

    for (int i = 0; i < count && n >= 16; i++) {
        memcpy(addrs, p, 16);
        n -= 16;
        p += 16;
    }
    *buf = p;
    return n;
}
