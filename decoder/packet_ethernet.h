#ifndef PACKET_ETHERNET_H
#define PACKET_ETHERNET_H

#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define ETH_802_3_MAX 1500
#define LLC_HDR_LEN 3
#define SNAP_HDR_LEN 5
#define ETH_802_LLC 0xffff

struct packet_data;

enum eth_802_type {
    ETH_802_UNKNOWN,
    ETH_802_STP = 0x4242,
    ETH_802_SNAP = 0xaaaa
};

void register_ethernet(void);

bool is_ethernet(struct packet_data *pdata);

#endif
