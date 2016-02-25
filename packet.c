#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include "packet.h"
#include "misc.h"
#include "error.h"
#include "output.h"

static void handle_ethernet(char *buffer);
static void handle_arp(char *buffer);
static void handle_ip(char *buffer);

void read_packet(int sockfd)
{
    char buffer[SNAPLEN];
    int n;

    memset(buffer, 0, SNAPLEN);
    if ((n = read(sockfd, buffer, SNAPLEN)) == -1) {
        err_sys("read error");
    }
    if (!capture) {
        handle_ip(buffer);
    } else {
        handle_ethernet(buffer);
    }
}

/*
 * Ethernet header
 *
 *       6           6       2
 * +-----------+-----------+---+
 * | Ethernet  | Ethernet  |   |
 * |destination|  source   |FT |
 * |  address  | address   |   |
 * +-----------+-----------+---+
 *
 */
void handle_ethernet(char *buffer)
{
    struct ethhdr *eth_header;

    eth_header = (struct ethhdr *) buffer;
    switch (ntohs(eth_header->h_proto)) {
    case ETH_P_IP:
        handle_ip(buffer + ETH_HLEN);
        break;
    case ETH_P_ARP:
        handle_arp(buffer + ETH_HLEN);
        break;
    default:
        //printf("Ethernet protocol: 0x%x\n", ntohs(eth_header->h_proto));
        break;
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
 *   ^   ^  ^ ^  ^
 *   |   |  | |  |
 *   |   |  | |  +-- Operation: 1 = ARP request,  2 =  ARP reply
 *   |   |  | |                 3 = RARP request, 4 = RARP reply
 *   |   |  | |
 *   |   |  | +-- Protocol Size, number of bytes
 *   |   |  |     in the requested network address.
 *   |   |  |     IP has 4-byte addresses, so 0x04.
 *   |   |  |
 *   |   |  +-- Hardware Size, number of bytes in
 *   |   |      the specified hardware address.
 *   |   |      Ethernet has 6-byte addresses, so 0x06.
 *   |   |
 *   |   +-- Protocol Type, 0x0800 = IP.
 *   |
 *   +-- Hardware Type, Ethernet = 0x0001.
 *
 */
void handle_arp(char *buffer)
{
    struct ether_arp *arp_header;
    struct arp_info info;

    arp_header = (struct ether_arp *) buffer;

    /* sender protocol address */
    if (inet_ntop(AF_INET, &arp_header->arp_spa, info.sip, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }

    /* target protocol address */
    if (inet_ntop(AF_INET, &arp_header->arp_tpa, info.tip, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }

    /* sender/target hardware address */
    snprintf(info.sha, HRDW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
             arp_header->arp_sha[2], arp_header->arp_sha[4], arp_header->arp_sha[5]);
    snprintf(info.tha, HRDW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
             arp_header->arp_tha[2], arp_header->arp_tha[4], arp_header->arp_tha[5]);

     /* arp opcode (command) */
    info.op = ntohs(arp_header->arp_op);

    print_arp(&info);
}

/*
 * IPv4 header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
*/
void handle_ip(char *buffer)
{
    struct iphdr *ip;
    char srcaddr[INET_ADDRSTRLEN];
    char dstaddr[INET_ADDRSTRLEN];

    ip = (struct iphdr *) buffer;
    if (inet_ntop(AF_INET, &ip->saddr, srcaddr, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
    if (inet_ntop(AF_INET, &ip->daddr, dstaddr, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
    if (memcmp(&ip->saddr, &local_addr->sin_addr, sizeof(ip->saddr)) == 0) {
        tx.num_packets++;
        tx.tot_bytes += ntohs(ip->tot_len);
    }
    if (memcmp(&ip->daddr, &local_addr->sin_addr, sizeof(ip->daddr)) == 0) {
        rx.num_packets++;
        rx.tot_bytes += ntohs(ip->tot_len);
    }
}
