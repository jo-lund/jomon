#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <stdlib.h>
#include <string.h>
#include "packet_arp.h"
#include "packet_ethernet.h"
#include "../error.h"
#include "packet.h"

#define ARP_SIZE 28 /* size of an ARP packet (header + payload) */
#ifdef __FreeBSD__
#define ARPHRD_EETHER 2
#define ARPHRD_AX25 3
#define ARPHRD_PRONET 4
#define ARPHRD_CHAOS 5
#define ARPHRD_ARCNET 7
#endif

extern void add_arp_information(void *w, void *sw, void *data);
extern void print_arp(char *buf, int n, void *data);

static struct protocol_info arp_prot = {
    .short_name = "ARP",
    .long_name = "Address Resolution Protocol",
    .decode = handle_arp,
    .print_pdu = print_arp,
    .add_pdu = add_arp_information
};

void register_arp()
{
    register_protocol(&arp_prot, ETHERNET_II, ETHERTYPE_ARP);
}

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
packet_error handle_arp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata)
{
    if (n < ARP_SIZE) return DECODE_ERR;

    struct ether_arp *arp_header;
    struct arp_info *arp;

    pinfo->num_packets++;
    pinfo->num_bytes += n;
    arp_header = (struct ether_arp *) buffer;
    arp = mempool_alloc(sizeof(struct arp_info));
    memcpy(arp->sip, arp_header->arp_spa, 4); /* sender protocol address */
    memcpy(arp->tip, arp_header->arp_tpa, 4); /* target protocol address */
    memcpy(arp->sha, arp_header->arp_sha, ETHER_ADDR_LEN); /* sender hardware address */
    memcpy(arp->tha, arp_header->arp_tha, ETHER_ADDR_LEN); /* target hardware address */
    arp->op = ntohs(arp_header->arp_op); /* arp opcode (command) */
    arp->ht = ntohs(arp_header->arp_hrd);
    arp->pt = ntohs(arp_header->arp_pro);
    arp->hs = arp_header->arp_hln;
    arp->ps = arp_header->arp_pln;
    pdata->data = arp;
    pdata->len = n;
    return NO_ERR;
}

char *get_arp_hardware_type(uint16_t type)
{
    switch (type) {
    case ARPHRD_ETHER:
        return "Ethernet";
    case ARPHRD_EETHER:
        return "Experimental Ethernet (3mb)";
    case ARPHRD_AX25:
        return "Amateur Radio AX.25";
    case ARPHRD_PRONET:
        return "Proteon ProNET Token Ring";
    case ARPHRD_CHAOS:
        return "Chaos";
    case ARPHRD_IEEE802:
        return "IEEE 802 networks";
    case ARPHRD_ARCNET:
        return "Arcnet";
    default:
        return NULL;
    }
}

char *get_arp_protocol_type(uint16_t type)
{
    switch (type) {
    case ETHERTYPE_IP:
        return "IPv4";
    case ETHERTYPE_ARP:
        return "Address resolution packet";
    case ETHERTYPE_IPV6:
        return "IPv6";
    default:
        return NULL;
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
        return NULL;
    }
}
