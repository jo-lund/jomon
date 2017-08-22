#include <string.h>
#include "packet_ethernet.h"
#include "packet_arp.h"
#include "packet_ip.h"
#include "packet_stp.h"

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
    p->eth.data = malloc(n);
    memcpy(p->eth.data, buffer, n);

    /* Ethernet 802.3 frame */
    if (p->eth.ethertype <= ETH_802_3_MAX) {
        unsigned char *ptr;

        ptr = buffer + ETH_HLEN;
        p->eth.payload_len = p->eth.ethertype;
        p->eth.llc = calloc(1, sizeof(struct eth_802_llc));
        p->eth.llc->dsap = ptr[0];
        p->eth.llc->ssap = ptr[1];
        p->eth.llc->control = ptr[2];

        /* Spanning Tree Protocol */
        if (p->eth.llc->dsap == 0x42 && p->eth.llc->ssap == 0x42) {
            p->perr = handle_stp(ptr + LLC_HDR_LEN, p->eth.ethertype - LLC_HDR_LEN,
                                p->eth.llc);
        } else if (p->eth.llc->dsap == 0xaa && p->eth.llc->ssap == 0xaa) {
            /* SNAP extension */
            p->eth.llc->snap = malloc(sizeof(struct snap_info));
            ptr += LLC_HDR_LEN;
            memcpy(p->eth.llc->snap->oui, ptr, 3);
            ptr += 3; /* skip first 3 bytes of 802.2 SNAP */
            p->eth.llc->snap->protocol_id = ptr[0] << 8 | ptr[1];

            /* TODO: If OUI is 0 I need to to handle the internet protocols that
               will be layered on top of SNAP */
        }
    } else { /* Ethernet II */
        p->eth.payload_len = n - ETH_HLEN;
        switch (p->eth.ethertype) {
        case ETH_P_IP:
            p->perr = handle_ipv4(buffer + ETH_HLEN, n - ETH_HLEN, &p->eth);
            break;
        case ETH_P_ARP:
            p->perr = handle_arp(buffer + ETH_HLEN, n - ETH_HLEN, &p->eth);
            break;
        case ETH_P_IPV6:
            p->perr = handle_ipv6(buffer + ETH_HLEN, n - ETH_HLEN, &p->eth);
            break;
        case ETH_P_PAE: /* TODO: not yet supported */
        default:
            p->perr = UNK_PROTOCOL;
            break;
        }
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

enum eth_802_type get_eth802_type(struct eth_802_llc *llc)
{
    /* DSAP and SSAP specify the upper layer protocols above LLC */
    if (llc->ssap == 0x42 && llc->dsap == 0x42) return ETH_802_STP;
    if (llc->ssap == 0xaa && llc->dsap == 0xaa) return ETH_802_SNAP;

    return ETH_802_UNKNOWN;
}

uint32_t get_eth802_oui(struct snap_info *snap)
{
    return snap->oui[0] << 16 | snap->oui[1] << 8 | snap->oui[2];
}

void free_ethernet802_3_frame(struct eth_info *eth)
{
    if (!eth || !eth->llc) return;

    if (eth->llc->dsap == 0xaa && eth->llc->ssap == 0xaa) {
        free(eth->llc->snap);
    } else if (eth->llc->dsap == 0x42 && eth->llc->ssap == 0x42) {
        free(eth->llc->bpdu);
    }
    free(eth->llc);
}
