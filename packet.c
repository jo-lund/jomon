#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include "packet.h"
#include "misc.h"
#include "error.h"
#include "output.h"

static void handle_ethernet(char *buffer);
static void handle_arp(char *buffer);
static void handle_ip(char *buffer);
static void handle_icmp(char *buffer);
static void handle_igmp(char *buffer);
static void handle_tcp(char *buffer, struct ip_info *info);
static void handle_udp(char *buffer, struct ip_info *info);
static bool handle_dns(char *buffer, struct udphdr *udp, struct ip_info *info);
static void check_address(char *buffer);

void read_packet(int sockfd)
{
    char buffer[SNAPLEN];
    int n;

    memset(buffer, 0, SNAPLEN);

    // TODO: Use recvfrom and read the sockaddr_ll struct.
    if ((n = read(sockfd, buffer, SNAPLEN)) == -1) {
        err_sys("read error");
    }
    if (!capture) {
        check_address(buffer);
    } else {
        handle_ethernet(buffer);
    }
}

void check_address(char *buffer)
{
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    struct iphdr *ip;

    ip = (struct iphdr *) buffer;
    if (inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
    if (inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }

    /* this can be optimized by only filtering for packets matching host ip address */
    if (memcmp(&ip->saddr, &local_addr->sin_addr, sizeof(ip->saddr)) == 0) {
        tx.num_packets++;
        tx.tot_bytes += ntohs(ip->tot_len);
    }
    if (memcmp(&ip->daddr, &local_addr->sin_addr, sizeof(ip->daddr)) == 0) {
        rx.num_packets++;
        rx.tot_bytes += ntohs(ip->tot_len);
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
    case ETH_P_IPV6:
        break;
    case ETH_P_PAE:
        break;
    default:
        printf("Ethernet protocol: 0x%x\n", ntohs(eth_header->h_proto));
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
    snprintf(info.sha, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
             arp_header->arp_sha[2], arp_header->arp_sha[4], arp_header->arp_sha[5]);
    snprintf(info.tha, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
             arp_header->arp_tha[2], arp_header->arp_tha[4], arp_header->arp_tha[5]);

    info.op = ntohs(arp_header->arp_op); /* arp opcode (command) */
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
 * IHL: Internet header length, the number of 32 bit words in the header.
 *      The minimum value for this field is 5: 5 * 32 = 160 bits (20 bytes).
 *
 * Protocol: Defines the protocol used in the data portion of the packet.
 *
*/
void handle_ip(char *buffer)
{
    struct iphdr *ip;
    struct ip_info info;
    int header_len;

    ip = (struct iphdr *) buffer;
    if (inet_ntop(AF_INET, &ip->saddr, info.src, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
    if (inet_ntop(AF_INET, &ip->daddr, info.dst, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
    info.protocol = ip->protocol;
    header_len = ip->ihl * 4;

    switch (ip->protocol) {
    case IPPROTO_ICMP:
        handle_icmp(buffer + header_len);
        break;
    case IPPROTO_IGMP:
        handle_igmp(buffer + header_len);
        break;
    case IPPROTO_TCP:
        handle_tcp(buffer + header_len, &info);
        break;
    case IPPROTO_UDP:
        handle_udp(buffer + header_len, &info);
        break;
    }
    print_ip(&info);
}

/*
 * UDP header
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Length             |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
void handle_udp(char *buffer, struct ip_info *info)
{
    struct udphdr *udp;
    
    udp = (struct udphdr *) buffer;
    info->udp.src_port = ntohs(udp->source);
    info->udp.dst_port = ntohs(udp->dest);
    handle_dns(buffer + UDP_HDRLEN, udp, info);
}

/*
 * Handle DNS message. Will return false if not DNS.
 * 
 * Format of message (http://tools.ietf.org/html/rfc1035):
 * +---------------------+
 * |        Header       |
 * +---------------------+
 * |       Question      | the question for the name server
 * +---------------------+
 * |        Answer       | RRs answering the question
 * +---------------------+
 * |      Authority      | RRs pointing toward an authority
 * +---------------------+
 * |      Additional     | RRs holding additional information
 * +---------------------+
 *
 * DNS header: 
 *
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * ID: A 16 bit identifier assigned by the program that
       generates any kind of query. This identifier is copied
       the corresponding reply and can be used by the requester
       to match up replies to outstanding queries.
 * QR: query = 0, response = 1
 * RCODE: Response code - this 4 bit field is set as part of responses.
 * QDCOUNT: an unsigned 16 bit integer specifying the number of
 *          entries in the question section.
 * ANCOUNT: an unsigned 16 bit integer specifying the number of
 *          resource records in the answer section.
 * NSCOUNT: an unsigned 16 bit integer specifying the number of name
 *          server resource records in the authority records section.
 * ARCOUNT: an unsigned 16 bit integer specifying the number of
 *          resource records in the additional records section.
 *
 */
bool handle_dns(char *buffer, struct udphdr *udp, struct ip_info *info)
{
    info->udp.dns.qr = -1;

    /* 
     * UDP header length (8 bytes) + DNS header length (12 bytes).
     * DNS Messages carried by UDP are restricted to 512 bytes (not counting the 
     * UDP header.
     */
    if (ntohs(udp->len < 20) || ntohs(udp->len) > 520) {
        return false;
    }

    /* DNS primarily uses UDP on port number 53 to serve requests */
    if (ntohs(udp->source) != 53 && ntohs(udp->dest) != 53) {
        return false;
    }

    if ((buffer[4] << 8 | buffer[5]) != 0x1) { /* the QDCOUNT will in practice always be one */
        return false;
    }
    
    if (buffer[2] & 0x80) { /* DNS response */
        info->udp.dns.qr = 1;
        info->udp.dns.rcode = buffer[3] & 0x0f; /* response code */
    } else { /* DNS query */
        if (buffer[3] & 0x0f != 0) { /* RCODE will be zero */
            return false;
        }
        /* ANCOUNT and NSCOUNT values are zero */
        if ((buffer[6] << 8 | buffer[7]) != 0 && (buffer[8] << 8 | buffer[9]) != 0) {
            return false;
        }
        /*
         * ARCOUNT will typically be 0, 1, or 2, depending on whether EDNS0
         * (RFC 2671) or TSIG (RFC 2845) are used
         */
        if ((buffer[10] << 8 | buffer[11]) > 2) {
            return false;
        }
        info->udp.dns.qr = 0;

        /* opcode - specifies the kind of query in the message */
        info->udp.dns.opcode = buffer[2] & 0x78;
    }
 
    return true;
}


void handle_icmp(char *buffer)
{

}

void handle_igmp(char *buffer)
{

}

void handle_tcp(char *buffer, struct ip_info *info)
{

}
