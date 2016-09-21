#ifndef PACKET_ARP_H
#define PACKET_ARP_H

#include <stdbool.h>

/* hardware address length (format aa:bb:cc:dd:ee:ff) */
#define HW_ADDRSTRLEN 18

struct arp_info {
    char sip[INET_ADDRSTRLEN];   /* sender IP address */
    char tip[INET_ADDRSTRLEN];   /* target IP address */
    char sha[HW_ADDRSTRLEN];     /* sender hardware address */
    char tha[HW_ADDRSTRLEN];     /* target hardware address */
    uint16_t ht;                 /* hardware type, e.g. Ethernet, Amateur radio */
    uint16_t pt;                 /* protocol type, IPv4 is 0x0800 */
    uint8_t hs;                  /* hardware size */
    uint8_t ps;                  /* protocol size */
    uint16_t op;                 /* ARP opcode */
};

struct eth_info;

bool handle_arp(unsigned char *buffer, int n, struct eth_info *info);
char *get_arp_hardware_type(uint16_t type);
char *get_arp_protocol_type(uint16_t type);
char *get_arp_opcode(uint16_t opcode);

#endif
