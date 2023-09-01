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

#define get_arp(p) ((struct arp_info *)(p)->root->next->data)
#define arp_sip(p) get_arp(p)->sip
#define arp_tip(p) get_arp(p)->tip
#define arp_sha(p) get_arp(p)->sha
#define arp_tha(p) get_arp(p)->tha
#define arp_hwtype(p) get_arp(p)->ht
#define arp_hwsize(p) get_arp(p)->hs
#define arp_ptype(p) get_arp(p)->pt
#define arp_psize(p) get_arp(p)->ps
#define arp_opcode(p) get_arp(p)->op

void register_arp(void);
packet_error handle_arp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata);
char *get_arp_hardware_type(uint16_t type);
char *get_arp_protocol_type(uint16_t type);
char *get_arp_opcode(uint16_t opcode);

#endif
