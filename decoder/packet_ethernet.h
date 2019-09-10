#ifndef PACKET_ETHERNET_H
#define PACKET_ETHERNET_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/if_ether.h>

#define ETH_802_3_MAX 1500
#define LLC_HDR_LEN 3
#define SNAP_HDR_LEN 5

#define LLC_PAYLOAD_LEN(p) ((p)->eth.ethertype - LLC_HDR_LEN)

struct packet;

enum eth_802_type {
    ETH_802_UNKNOWN,
    ETH_802_STP,
    ETH_802_SNAP
};

/* 802.2 SNAP */
struct snap_info {
    unsigned char oui[3]; /* IEEE Organizationally Unique Identifier */
    uint16_t protocol_id; /* If OUI is 0 the protocol ID is the Ethernet type */
    union {
        struct arp_info *arp;
        struct ipv4_info *ip;
    };
};

/* Ethernet 802.2 Logical Link Control */
struct eth_802_llc {
    uint8_t dsap; /* destination service access point */
    uint8_t ssap; /* source service access point */
    uint8_t control; /* possible to be 2 bytes? */
    union {
        struct snap_info *snap;
        struct stp_info *bpdu;
    };
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

enum eth_802_type get_eth802_type(struct eth_802_llc *llc);
uint32_t get_eth802_oui(struct snap_info *snap);
char *get_ethernet_type(uint16_t ethertype);

/* Should be internal to the decoder */
bool handle_ethernet(unsigned char *buffer, int n, struct packet *p);

#endif
