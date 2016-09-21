#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <netinet/ip_icmp.h>
#include <linux/igmp.h>
#include "util.h"
#include "vector.h"
#include "error.h"
#include <packet.h>

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

void gethost(char *addr, char *host, int hostlen)
{
    struct sockaddr_in saddr;
    struct in_addr naddr;

    inet_pton(AF_INET, addr, &naddr);
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr = naddr;
    getnameinfo((struct sockaddr *) &saddr, sizeof(struct sockaddr_in),
                host, hostlen, NULL, 0, 0);
}

int snprintcat(char *buf, int size, char *fmt, ...)
{
    va_list ap;
    int len;
    int n;

    len = strnlen(buf, size);
    va_start(ap, fmt);
    n = vsnprintf(buf + len, size - len, fmt, ap);
    va_end(ap);
    return n;
}

char *strtolower(char *str)
{
    char *ptr = str;

    while (*ptr != '\0') {
        *ptr = tolower(*ptr);
        ptr++;
    }
    return str;
}

int get_max_namelen(struct dns_resource_record *record, int n)
{
    int maxlen = 0;

    for (int i = 0; i < n; i++) {
        int len = strlen(record[i].name);
        if (len > maxlen) {
            maxlen = len;
        }
    }
    return maxlen;
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

char *get_icmp_type(uint8_t type)
{
    switch (type) {
    case ICMP_ECHOREPLY:
        return "Echo Reply";
    case ICMP_DEST_UNREACH:
        return "Destination Unreachable";
    case ICMP_SOURCE_QUENCH:
        return "Source Quench";
    case ICMP_REDIRECT:
        return "Redirect (change route)";
    case ICMP_ECHO:
        return "Echo Request";
    case ICMP_TIME_EXCEEDED:
        return "Time Exceeded";
    case ICMP_PARAMETERPROB:
        return "Parameter Problem";
    case ICMP_TIMESTAMP:
        return "Timestamp Request";
    case ICMP_TIMESTAMPREPLY:
        return "Timestamp Reply";
    case ICMP_INFO_REQUEST:
        return "Information Request";
    case ICMP_INFO_REPLY:
        return "Information Reply";
    case ICMP_ADDRESS:
        return "Address Mask Request";
    case ICMP_ADDRESSREPLY:
        return "Address Mask Reply";
    default:
        return "";
    }
}

char *get_icmp_dest_unreach_code(uint8_t code)
{
    switch (code) {
    case ICMP_NET_UNREACH:
        return "Network Unreachable";
    case ICMP_HOST_UNREACH:
        return "Host Unreachable";
    case ICMP_PROT_UNREACH:
        return "Protocol Unreachable";
    case ICMP_PORT_UNREACH:
        return "Port Unreachable";
    case ICMP_FRAG_NEEDED:
        return "Fragmentation Needed/DF set";
    case ICMP_SR_FAILED:
        return "Source Route failed";
    case ICMP_PKT_FILTERED:
        return "Packet filtered";
    case ICMP_PREC_VIOLATION:
        return "Precedence violation";
    case ICMP_PREC_CUTOFF:
        return "Precedence cut off";
    default:
        return "";
    }
}

char *get_igmp_type(uint8_t type)
{
    switch (type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        return "Membership query";
    case IGMP_HOST_MEMBERSHIP_REPORT:
        return "Version 1 Membership report";
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
        return "Version 2 Membership report";
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
        return "Version 3 Membership report";
    case IGMP_HOST_LEAVE_MESSAGE:
        return "Leave group";
    case IGMP_PIM:
        return "";
    default:
        return "";
    }
}

char *get_stp_bpdu_type(uint8_t type)
{
    switch (type) {
    case CONFIG:
        return "Configuration BPDU";
    case RST:
        return "Rapid Spanning Tree BPDU";
    case TCN:
        return "Topology Change Notification BPDU";
    default:
        return "";
    }
}

char *get_transport_protocol(uint8_t protocol)
{
    switch (protocol) {
    case IPPROTO_ICMP:
        return "ICMP";
    case IPPROTO_IGMP:
        return "IGMP";
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    default:
        return NULL;
    }
}
