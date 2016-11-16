#ifndef PACKET_ARP_H
#define PACKET_ARP_H

#include <stdbool.h>
#include <linux/if_ether.h>

/* hardware address length (format aa:bb:cc:dd:ee:ff) */
#define HW_ADDRSTRLEN 18

#define HW_ADDR_NTOP(dst, src)                                      \
    snprintf(dst, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",   \
             src[0], src[1], src[2], src[3], src[4], src[5])

struct arp_info {
    uint8_t sip[4];        /* sender IP address */
    uint8_t tip[4];        /* target IP address */
    uint8_t sha[ETH_ALEN]; /* sender hardware address */
    uint8_t tha[ETH_ALEN]; /* target hardware address */
    uint16_t ht;           /* hardware type, e.g. Ethernet, Amateur radio */
    uint16_t pt;           /* protocol type, IPv4 is 0x0800 */
    uint8_t hs;            /* hardware size */
    uint8_t ps;            /* protocol size */
    uint16_t op;           /* ARP opcode */
};

struct eth_info;

bool handle_arp(unsigned char *buffer, int n, struct eth_info *info);
char *get_arp_hardware_type(uint16_t type);
char *get_arp_protocol_type(uint16_t type);
char *get_arp_opcode(uint16_t opcode);

#endif
