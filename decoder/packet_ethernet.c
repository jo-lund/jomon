#include <string.h>
#include "packet_ethernet.h"
#include "packet_arp.h"
#include "packet_ip.h"
#include "packet_stp.h"
#include "../util.h"
#include "../interface.h"

#define MAX_PACKET_SIZE 65535
#ifdef __linux__
#define ETHERTYPE_PAE ETH_P_PAE
#endif

extern void add_ethernet_information(void *w, void *sw, void *data);
static packet_error handle_ethernet(struct protocol_info *pinfo, unsigned char *buffer,
                                    int n, struct packet_data *pdata);

static struct protocol_info eth2 = {
    .short_name = "ETH",
    .long_name = "Ethernet II",
    .decode = handle_ethernet,
    .print_pdu = NULL,
    .add_pdu = add_ethernet_information
};

static struct protocol_info eth802 = {
    .short_name = "ETH",
    .long_name = "Ethernet 802.3",
    .decode = handle_ethernet,
    .print_pdu = NULL,
    .add_pdu = add_ethernet_information
};

void register_ethernet(void)
{
    register_protocol(&eth2, DATALINK, LINKTYPE_ETHERNET);
    register_protocol(&eth802, DATALINK, LINKTYPE_IEEE802);
}

/*
 * Ethernet header
 *
 *       6           6       2
 * +-----------+-----------+---+
 * | Ethernet  | Ethernet  |   |
 * |destination|  source   |FT |
 * |  address  | address   |   |
 * +-----------+-----------+---+
 *
 * FT, the frame type or EtherType, can be used for two different purposes.
 * Values of 1500 and below (Ethernet 802.3) mean that it is used to indicate
 * the size of the payload in bytes, while values of 1536 and above (Ethernet II)
 * indicate that it is used as an EtherType, to indicate which protocol is
 * encapsulated in the payload of the frame.
 *
 * There are several types of 802.3 frames, e.g. 802.2 LLC (Logical Link Control)
 * and 802.2 SNAP (Subnetwork Access Protocol).
 *
 * 802.2 LLC Header
 *
 *     1        1         1
 * +--------+--------+--------+
 * | DSAP=K1| SSAP=K1| Control|
 * +--------+--------+--------+
 *
 * 802.2 SNAP Header
 *
 * When SNAP extension is used, it is located right after the LLC header. The
 * payload start bytes for SNAP is 0xaaaa, which means the K1 value is 0xaa.
 * The control value is 3 (Unnumbered Information).
 *
 * +--------+--------+---------+--------+--------+
 * |Protocol Id or Org Code =K2|    EtherType    |
 * +--------+--------+---------+--------+--------+
 *
 * The K2 value is 0 (zero).
 */

packet_error handle_ethernet(struct protocol_info *pinfo UNUSED, unsigned char *buffer,
                             int n, struct packet_data *pdata)
{
    if (n < ETHER_HDR_LEN || n > MAX_PACKET_SIZE)
        return DATALINK_ERR;

    struct ether_header *eth_header;
    struct eth_info *eth;
    struct protocol_info *layer2;
    uint32_t id;

    eth_header = (struct ether_header *) buffer;
    eth = mempool_alloc(sizeof(struct eth_info));
    memcpy(eth->mac_src, eth_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth->mac_dst, eth_header->ether_dhost, ETHER_ADDR_LEN);
    eth->ethertype = ntohs(eth_header->ether_type);
    pdata->data = eth;
    pdata->len = ETHER_HDR_LEN;
    pdata->prev = NULL;
    if (eth->ethertype <= ETH_802_3_MAX) {
        id = get_protocol_id(ETH802_3, ETH_802_LLC);
        layer2 = get_protocol(id);
        pdata->id = get_protocol_id(DATALINK, LINKTYPE_IEEE802);
    } else {
        id = get_protocol_id(ETHERNET_II, eth->ethertype);
        layer2 = get_protocol(id);
    }
    if (layer2) {
        pdata->next = mempool_calloc(1, struct packet_data);
        pdata->next->prev = pdata;
        pdata->next->id = id;
        layer2->decode(layer2, buffer + ETHER_HDR_LEN, n - ETHER_HDR_LEN,
                       pdata->next);
        return NO_ERR;
    }
    return UNK_PROTOCOL;
}

char *get_ethernet_type(uint16_t ethertype)
{
    switch (ethertype) {
    case ETHERTYPE_IP:
        return "IPv4";
    case ETHERTYPE_ARP:
        return "ARP";
    case ETHERTYPE_IPV6:
        return "IPv6";
    case ETHERTYPE_PAE:
        return "Port Access Entity";
    default:
        return NULL;
    }
}
