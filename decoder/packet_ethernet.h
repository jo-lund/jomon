#ifndef PACKET_ETHERNET_H
#define PACKET_ETHERNET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/if_ether.h>

#define ETH_802_3_MAX 1500
#define LLC_HDR_LEN 3
#define SNAP_HDR_LEN 5

#define ETH_802_LLC 0xffff
#define LLC_PAYLOAD_LEN(eth) ((eth)->ethertype - LLC_HDR_LEN)

struct packet;

enum eth_802_type {
    ETH_802_UNKNOWN,
    ETH_802_STP = 0x4242,
    ETH_802_SNAP = 0xaaaa
};

struct eth_info {
    unsigned char mac_src[ETHER_ADDR_LEN];
    unsigned char mac_dst[ETHER_ADDR_LEN];
    uint16_t ethertype;
};

#define ethertype(p) ((struct eth_info *)(p)->root->data)->ethertype
#define eth_src(p) ((struct eth_info *)(p)->root->data)->mac_src
#define eth_dst(p) ((struct eth_info *)(p)->root->data)->mac_dst
#define eth_len(p) ((p)->len - ETH_HLEN)

void register_ethernet(void);
char *get_ethernet_type(uint16_t ethertype);

#endif
