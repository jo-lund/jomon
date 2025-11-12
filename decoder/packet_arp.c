#include <arpa/inet.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include "packet_arp.h"
#include "packet.h"
#include "error.h"
#include "field.h"
#include "string.h"
#include "util.h"

#define ARP_SIZE 28 /* size of an ARP packet (header + payload) */
#ifdef __FreeBSD__
#define ARPHRD_EETHER 2
#define ARPHRD_AX25 3
#define ARPHRD_PRONET 4
#define ARPHRD_CHAOS 5
#define ARPHRD_ARCNET 7
#endif

static void print_arp(char *buf, int n, struct packet_data *pdata);
static packet_error handle_arp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                               struct packet_data *pdata);

static struct protocol_info arp = {
    .short_name = "ARP",
    .long_name = "Address Resolution Protocol",
    .decode = handle_arp,
    .print_pdu = print_arp,
};

void register_arp(void)
{
    register_protocol(&arp, ETHERNET_II, ETHERTYPE_ARP);
}

static char *get_arp_hardware_type(uint16_t type)
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

static char *get_arp_protocol_type(uint16_t type)
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

static char *get_arp_opcode(uint16_t opcode)
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
packet_error handle_arp(struct protocol_info *pinfo, unsigned char *buf, int n, struct packet_data *pdata)
{
    struct uint_string type;

    if (n < ARP_SIZE) {
        pdata->error = create_error_string("Packet length (%d) less than minimum ARP packet (%d)",
                                           n, ARP_SIZE);
        return DECODE_ERR;
    }
    field_init(&pdata->data);
    type.val = read_uint16be(&buf);
    type.str = get_arp_hardware_type(type.val);
    field_add_value(&pdata->data, "Hardware type", FIELD_UINT_STRING, &type);
    type.val = read_uint16be(&buf);
    type.str = get_arp_protocol_type(type.val);
    field_add_value(&pdata->data, "Protocol type", FIELD_UINT_STRING, &type);
    field_add_value(&pdata->data, "Hardware size", FIELD_UINT8, UINT_TO_PTR(*buf));
    buf++;
    field_add_value(&pdata->data, "Protocol size", FIELD_UINT8, UINT_TO_PTR(*buf));
    buf++;
    type.val = read_uint16be(&buf);
    type.str = get_arp_opcode(type.val);
    field_add_value(&pdata->data, "Opcode", FIELD_UINT_STRING, &type);
    field_add_bytes(&pdata->data, "Sender MAC address", FIELD_HWADDR, buf, ETHER_ADDR_LEN);
    buf += ETHER_ADDR_LEN;
    field_add_value(&pdata->data, "Sender IP address", FIELD_IP4ADDR, UINT_TO_PTR(read_uint32le(&buf)));
    field_add_bytes(&pdata->data, "Target MAC address", FIELD_HWADDR, buf, ETHER_ADDR_LEN);
    buf += ETHER_ADDR_LEN;
    field_add_value(&pdata->data, "Target IP address", FIELD_IP4ADDR, UINT_TO_PTR(read_uint32le(&buf)));
    pdata->len = n;  // TODO: Handle padding
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    return NO_ERR;
}

void print_arp(char *buf, int n, struct packet_data *pdata)
{
    char sip[INET_ADDRSTRLEN];
    char tip[INET_ADDRSTRLEN];
    char *sha;
    const struct field *f;
    uint32_t addr;
    struct uint_string *opcode;

    f = field_search(&pdata->data, "Sender IP address");
    addr = field_get_uint32(f);
    inet_ntop(AF_INET, &addr, sip, INET_ADDRSTRLEN);
    f = field_search(&pdata->data, "Target IP address");
    addr = field_get_uint32(f);
    inet_ntop(AF_INET, &addr, tip, INET_ADDRSTRLEN);
    opcode = field_search_value(&pdata->data, "Opcode");
    switch (opcode->val) {
    case ARPOP_REQUEST:
        snprintf(buf, n, "Request: Looking for hardware address for %s", tip);
        break;
    case ARPOP_REPLY:
        sha = field_search_value(&pdata->data, "Sender MAC address");
        HW_ADDR_NTOP(sha, sha);
        snprintf(buf, n, "Reply: %s has hardware address %s", sip, sha);
        break;
    default:
        snprintf(buf, n, "Opcode %d", opcode->val);
        break;
    }
}
