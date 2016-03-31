#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include "util.h"
#include "packet.h"
#include "vector.h"

#include <stdio.h>
#include "error.h"
#include <netinet/if_ether.h>

/*
 * Transform a hex string in the format aa:bb:cc:dd:ee:ff to its integer
 * representation stored in a char array of size 6.
 */
static bool hextoint(unsigned char dest[], char *src)
{
    if (strlen(src) != HW_ADDRSTRLEN) return false;

    uint8_t res;
    char *end;
    int i = 0;

    do {
        errno = 0;
        res = strtoul(src, &end, 16);
        if ((errno != 0 && res == 0) || (i < 5 && *end != ':')) {
            return false;
        }
        dest[i++] = res;
        src += 3;
    } while (*end != '\0' && i < 6);

    return true;
}

void serialize_arp(unsigned char *buf, struct arp_info *info)
{
    /* ARP header */
    buf[0] = info->ht >> 8;
    buf[1] = info->ht & 0x00ff;
    buf[2] = info->pt >> 8;
    buf[3] = info->pt & 0x00ff;
    buf[4] = info->hs;
    buf[5] = info->ps;
    buf[6] = info->op >> 8;
    buf[7] = info->op & 0x00ff;

    /* ARP payload */
    hextoint(buf + 8, info->sha);
    inet_pton(AF_INET, info->sip, buf + 14);
    hextoint(buf + 18, info->tha);
    inet_pton(AF_INET, info->tip, buf + 24);
}

const char *get_arp_hardware_type(uint16_t type)
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

const char *get_arp_protocol_type(uint16_t type)
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

const char *get_arp_opcode(uint16_t opcode)
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
