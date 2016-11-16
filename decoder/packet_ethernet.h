#ifndef PACKET_ETHERNET_H
#define PACKET_ETHERNET_H

#include <stdint.h>
#include <stdbool.h>
#include <linux/if_ether.h>

#define ETHERNET_HDRLEN 14

enum eth_802_type {
    ETH_802_UNKNOWN,
    ETH_802_STP,
    ETH_802_SNAP
};

/* 802.2 SNAP */
struct snap_info {
    unsigned char oui[3]; /* IEEE Organizationally Unique Identifier */
    uint16_t protocol_id; /* If OUI is 0 the protocol ID is the Ethernet type */
    uint16_t payload_len; /* length of payload if unknown payload */
    union {
        struct arp_info *arp;
        struct ip_info *ip;
        unsigned char *payload;
    };
};

/* Ethernet 802.2 Logical Link Control */
struct eth_802_llc {
    uint8_t dsap; /* destination service access point */
    uint8_t ssap; /* source service access point */
    uint8_t control; /* possible to be 2 bytes? */
    uint16_t payload_len; /* length of payload if unknown payload */
    union {
        struct snap_info *snap;
        struct stp_info *bpdu;
        unsigned char *payload;
    };
};

struct eth_info {
    unsigned char mac_src[ETH_ALEN];
    unsigned char mac_dst[ETH_ALEN];
    uint16_t ethertype;
    uint16_t payload_len; /* length of payload if ethertype is unknown */
    union {
        struct eth_802_llc *llc;
        struct arp_info *arp;
        struct ip_info *ip;
        unsigned char *payload;
    };
};

enum eth_802_type get_eth802_type(struct eth_802_llc *llc);
uint32_t get_eth802_oui(struct snap_info *snap);
char *get_ethernet_type(uint16_t ethertype);

/* Should be internal to the decoder */
bool handle_ethernet(unsigned char *buffer, int n, struct eth_info *eth);

#endif

