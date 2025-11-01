#ifndef PACKET_ARP_H
#define PACKET_ARP_H

#include <stdbool.h>
#include "packet.h"

struct arp_info {
    uint8_t sip[4];        /* sender IP address */
    uint8_t tip[4];        /* target IP address */
    uint8_t sha[ETHER_ADDR_LEN]; /* sender hardware address */
    uint8_t tha[ETHER_ADDR_LEN]; /* target hardware address */
    uint16_t ht;           /* hardware type, e.g. Ethernet, Amateur radio */
    uint16_t pt;           /* protocol type, IPv4 is 0x0800 */
    uint8_t hs;            /* hardware size */
    uint8_t ps;            /* protocol size */
    uint16_t op;           /* ARP opcode */
};

void register_arp(void);

#endif
