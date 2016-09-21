#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <stdlib.h>
#include <stdio.h>
#include "packet.h"
#include "../error.h"

#define ARP_SIZE 28 /* size of an ARP packet (header + payload) */

/*
 * IPv4 over Ethernet ARP packet (28 bytes)
 *
 *   2   2  1 1  2       6         4           6       4
 * +---+---+-+-+---+-----------+-------+-----------+-------+
 * |   |   |H|P|   |  Sender   | Sender|  Target   |Target |
 * |HT |PT |S|S|OP | Ethernet  |  IP   | Ethernet  |  IP   |
 * |   |   | | |   |  Address  |Address|  Address  |Address|
 * +---+---+-+-+---+-----------+-------+-----------+-------+
 *
 * HT: Hardware Type
 * PT: Protocol Type
 * HS: Hardware Size, number of bytes in the specified hardware address
 * PS: Protocol Size, number of bytes in the requested network address
 * OP: Operation. 1 = ARP request, 2 = ARP reply, 3 = RARP request, 4 = RARP reply
 */
bool handle_arp(unsigned char *buffer, int n, struct eth_info *eth)
{
    if (n < ARP_SIZE) return false;

    struct ether_arp *arp_header;

    arp_header = (struct ether_arp *) buffer;
    eth->arp = malloc(sizeof(struct arp_info));

    /* sender protocol address */
    if (inet_ntop(AF_INET, &arp_header->arp_spa, eth->arp->sip, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }

    /* target protocol address */
    if (inet_ntop(AF_INET, &arp_header->arp_tpa, eth->arp->tip, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }

    /* sender/target hardware address */
    snprintf(eth->arp->sha, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
             arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
    snprintf(eth->arp->tha, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
             arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);

    eth->arp->op = ntohs(arp_header->arp_op); /* arp opcode (command) */
    eth->arp->ht = ntohs(arp_header->arp_hrd);
    eth->arp->pt = ntohs(arp_header->arp_pro);
    eth->arp->hs = arp_header->arp_hln;
    eth->arp->ps = arp_header->arp_pln;
    return true;
}

char *get_arp_hardware_type(uint16_t type)
{
    switch (type) {
    case ARPHRD_ETHER:
        return "Ethernet";
    case ARPHRD_IEEE802:
        return "IEEE 802 networks";
    default:
        return "";
    }
}

char *get_arp_protocol_type(uint16_t type)
{
    switch (type) {
    case ETH_P_IP:
        return "IPv4";
    case ETH_P_ARP:
        return "Address resolution packet";
    case ETH_P_IPV6:
        return "IPv6";
    default:
        return "";
    }
}

char *get_arp_opcode(uint16_t opcode)
{
    switch (opcode) {
    case ARPOP_REQUEST:
        return "ARP request";
    case ARPOP_REPLY:
        return "ARP reply";
    default:
        return "";
    }
}
