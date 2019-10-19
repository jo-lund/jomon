#include <string.h>
#include "packet_ethernet.h"
#include "packet_arp.h"
#include "packet_ip.h"
#include "packet_stp.h"
#include "../util.h"

#define MAX_PACKET_SIZE 65535

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
bool handle_ethernet(unsigned char *buffer, int n, struct packet *p)
{
    if (n < ETH_HLEN || n > MAX_PACKET_SIZE) return false;

    struct ethhdr *eth_header;

    eth_header = (struct ethhdr *) buffer;
    memcpy(p->eth.mac_src, eth_header->h_source, ETH_ALEN);
    memcpy(p->eth.mac_dst, eth_header->h_dest, ETH_ALEN);
    p->eth.ethertype = ntohs(eth_header->h_proto);

    /* store the original frame in data */
    p->eth.data = mempool_pecopy(buffer, n);

    /* Ethernet 802.3 frame */
    if (p->eth.ethertype <= ETH_802_3_MAX) {
        struct protocol_info *pinfo;

        p->eth.payload_len = p->eth.ethertype;
        if ((pinfo = get_protocol(LAYER802_3, ETH_802_LLC)))
            p->perr = pinfo->decode(pinfo, buffer + ETH_HLEN, n - ETH_HLEN, &p->eth);
        else
            p->perr = UNK_PROTOCOL;
    } else { /* Ethernet II */
        struct protocol_info *pinfo;

        p->eth.payload_len = n - ETH_HLEN;
        if ((pinfo = get_protocol(LAYER2, ethertype(p))))
            p->perr = pinfo->decode(pinfo, buffer + ETH_HLEN, n - ETH_HLEN, &p->eth);
        else
            p->perr = UNK_PROTOCOL;
    }
    p->ptype = ETHERNET;
    return true;
}

char *get_ethernet_type(uint16_t ethertype)
{
    switch (ethertype) {
    case ETH_P_IP:
        return "IPv4";
    case ETH_P_ARP:
        return "ARP";
    case ETH_P_IPV6:
        return "IPv6";
    case ETH_P_PAE:
        return "Port Access Entity";
    default:
        return NULL;
    }
}
