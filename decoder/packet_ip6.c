#include <sys/types.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include "packet_ip6.h"
#include "packet_ip.h"
#include "packet.h"
#include "util.h"
#include "field.h"
#include "string.h"

extern char *get_ip_transport_protocol(uint8_t protocol);
static void print_ipv6(char *buf, int n, struct packet_data *pdata);
static packet_error handle_ipv6(struct protocol_info *pinfo, unsigned char *buffer, int n,
                                struct packet_data *pdata);

static char *dscp[48] = {
    [CS0] = "Default",
    [CS1] = "Class Selector 1",
    [CS2] = "Class Selector 2",
    [CS3] = "Class Selector 3",
    [CS4] = "Class Selector 4",
    [CS5] = "Class Selector 5",
};

static char *ecn[] = {
    "Not ECN-Capable",
    "ECT(1)",
    "ECT(0)",
    "CE",
};

static struct packet_flags tos[] = {
    { "Differentiated Services Code Point (DSCP)", 6, dscp },
    { "Explicit Congestion Notification (ECN)", 2, ecn },
};

static struct protocol_info ipv6_prot = {
    .short_name = "IPv6",
    .long_name = "Internet Protocol Version 6",
    .decode = handle_ipv6,
    .print_pdu = print_ipv6,
};

void register_ip6(void)
{
    register_protocol(&ipv6_prot, ETHERNET_II, ETHERTYPE_IPV6);
    register_protocol(&ipv6_prot, PKT_LOOP, ETHERTYPE_IPV6);
    register_protocol(&ipv6_prot, PKT_RAW, ETHERTYPE_IPV6);
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
packet_error handle_ipv6(struct protocol_info *pinfo, unsigned char *buf, int n,
                         struct packet_data *pdata)
{
    unsigned int header_len;
    uint32_t id, flow_label;
    uint8_t version;
    struct uint_string next_header;

    header_len = sizeof(struct ip6_hdr);
    if ((unsigned int) n < header_len) {
        pdata->len = n;
        pdata->error = create_error_string("Packet length (%d) less than IP6 header length (%d)",
                                           n, header_len);
        return DECODE_ERR;
    }

    field_init(&pdata->data);
    version = buf[0] >> 4;
    if (version != 6)
        pdata->error = create_error_string("IP6 version error %d != 6", version);

    field_add_value(&pdata->data, "Version", FIELD_UINT8, UINT_TO_PTR(version));
    field_add_bitfield(&pdata->data, "Traffic class", (buf[0] & 0x0f) << 4 | (buf[1] & 0xf0) >> 4,
                       false, tos, ARRAY_SIZE(tos));
    buf++;
    flow_label = (buf[0] & 0x0f) << 16 | buf[1] << 8 | buf[2];
    field_add_value(&pdata->data, "Flow label", FIELD_UINT32, UINT_TO_PTR(flow_label));
    buf += 3;
    field_add_value(&pdata->data, "Payload length", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buf)));
    next_header.val = *buf++;
    next_header.str = get_ip_transport_protocol(next_header.val);
    field_add_value(&pdata->data, "Next header", FIELD_UINT_STRING, &next_header);
    field_add_value(&pdata->data, "Hop limit", FIELD_UINT8, UINT_TO_PTR(*buf++));
    field_add_bytes(&pdata->data, "Source address", FIELD_IP6ADDR, buf, 16);
    buf += 16;
    field_add_bytes(&pdata->data, "Destination address", FIELD_IP6ADDR, buf, 16);
    buf += 16;
    pdata->len = header_len;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    id = get_protocol_id(IP6_PROT, next_header.val);

    // TODO: Handle IPv6 extension headers and errors
    struct protocol_info *layer3 = get_protocol(id);
    if (layer3) {
        pdata->next = mempool_calloc(1, struct packet_data);
        pdata->next->id = id;
        if (layer3->decode(layer3, buf, n - header_len, pdata->next) == UNK_PROTOCOL) {
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

static void print_ipv6(char *buf, int n, struct packet_data *pdata)
{
    struct uint_string *next_header;

    next_header = field_search_value(&pdata->data, "Next header");
    snprintf(buf, n, "Next header: %u", next_header->val);
}

bool is_ipv6(struct packet_data *pdata)
{
    struct protocol_info *pinfo = get_protocol(pdata->id);
    return strcmp(pinfo->short_name, "IPv6") == 0;
}
