#ifndef PACKET_ETHERNET_H
#define PACKET_ETHERNET_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/if_ether.h>

#define ETH_802_3_MAX 1500
#define LLC_HDR_LEN 3
#define SNAP_HDR_LEN 5

#define ETH_802_LLC 0xffff
#define LLC_PAYLOAD_LEN(p) ((p)->eth.ethertype - LLC_HDR_LEN)

struct packet;

enum eth_802_type {
    ETH_802_UNKNOWN,
    ETH_802_STP = 0x4242,
    ETH_802_SNAP = 0xaaaa
};

struct eth_info {
    unsigned char mac_src[ETH_ALEN];
    unsigned char mac_dst[ETH_ALEN];
    uint16_t ethertype;
    uint16_t payload_len; /* for 802.3 frames ethertype contains the payload length */
    unsigned char *data; /* contains the frame as seen on the network */
    union {
        struct eth_802_llc *llc;
        struct arp_info *arp;
        struct ipv4_info *ipv4;
        struct ipv6_info *ipv6;
    };
};

#define ethertype(p) ((p)->eth.ethertype)
#define eth_src(p) ((p)->eth.mac_src)
#define eth_dst(p) ((p)->eth.mac_dst)
#define eth_len(p) ((p)->eth.payload_len)
#define get_llc(p) ((p)->eth.llc)

char *get_ethernet_type(uint16_t ethertype);

/* Should be internal to the decoder */
bool handle_ethernet(unsigned char *buffer, int n, struct packet *p);

#endif
