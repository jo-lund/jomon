#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <stdlib.h>
#include <string.h>
#include "packet_arp.h"
#include "packet_ethernet.h"
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
    memcpy(eth->arp->sip, arp_header->arp_spa, 4); /* sender protocol address */
    memcpy(eth->arp->tip, arp_header->arp_tpa, 4); /* target protocol address */
    memcpy(eth->arp->sha, arp_header->arp_sha, ETH_ALEN); /* sender hardware address */
    memcpy(eth->arp->tha, arp_header->arp_tha, ETH_ALEN); /* target hardware address */
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
