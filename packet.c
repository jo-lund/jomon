#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <linux/igmp.h>
#include <ctype.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include "packet.h"
#include "misc.h"
#include "error.h"

#define DNS_PTR_LEN 2

static void handle_arp(unsigned char *buffer, struct arp_info *info);
static void handle_ip(unsigned char *buffer, struct ip_info *info);
static void handle_icmp(unsigned char *buffer, struct ip_info *info);
static void handle_igmp(unsigned char *buffer, struct ip_info *info);
static bool handle_tcp(unsigned char *buffer, struct ip_info *info);
static bool handle_udp(unsigned char *buffer, struct ip_info *info);
static bool check_port(unsigned char *buffer, struct application_info *info, uint16_t port, uint16_t packet_len);
static void check_address(unsigned char *buffer);
static void free_protocol_data(struct application_info *info);

/* application layer protocol handlers */
static bool handle_dns(unsigned char *buffer, struct application_info *info);
static bool handle_nbns(unsigned char *buffer, struct application_info *info);
static bool handle_ssdp(unsigned char *buffer, struct application_info *info, uint16_t len);
static bool handle_http(unsigned char *buffer, struct application_info *info);
static int parse_dns_name(unsigned char *buffer, unsigned char *ptr, char name[]);
static void parse_dns_record(int i, unsigned char *buffer, unsigned char **ptr, struct dns_info *info);
static void decode_nbns_name(char *dest, char *src);
static void parse_nbns_record(int i, unsigned char *buffer, unsigned char **ptr, struct nbns_info *info);
static void parse_ssdp(char *str, int n, list_t **msg_header);

size_t read_packet(int sockfd, unsigned char *buffer, size_t len, struct packet **p)
{
    int n;

    *p = malloc(sizeof(struct packet));
    if ((n = read(sockfd, buffer, len)) == -1) {
        free_packet(*p);
        err_sys("read error");
    }
    // TODO: This needs to be handled differently
    if (statistics) {
        check_address(buffer);
    } else if (!handle_ethernet(buffer, *p)) {
        free_packet(*p);
        return 0;
    }
    return n;
}

void free_packet(void *data)
{
    struct packet *p = (struct packet *) data;

    if (p->ptype == IPv4) {
        switch (p->ip.protocol) {
        case IPPROTO_UDP:
            free_protocol_data(&p->ip.udp.data);
            break;
        case IPPROTO_TCP:
            free_protocol_data(&p->ip.tcp.data);
            break;
        default:
            break;
        }
    }
    free(p);
}

void free_protocol_data(struct application_info *info)
{
    switch (info->utype) {
    case DNS:
        if (info->dns->record) {
            free(info->dns->record);
        }
        free(info->dns);
        break;
    case NBNS:
        if (info->nbns->record) {
            free(info->nbns->record);
        }
        free(info->nbns);
        break;
    case SSDP:
        list_free(info->ssdp);
        break;
    default:
        break;
    }
}

void check_address(unsigned char *buffer)
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
bool handle_ethernet(unsigned char *buffer, struct packet *p)
{
    struct ethhdr *eth_header;

    eth_header = (struct ethhdr *) buffer;
    switch (ntohs(eth_header->h_proto)) {
    case ETH_P_IP:
    {
        handle_ip(buffer + ETH_HLEN, &p->ip);
        p->ptype = IPv4;
        return true;
    }
    case ETH_P_ARP:
    {
        handle_arp(buffer + ETH_HLEN, &p->arp);
        p->ptype = ARP;
        return true;
    }
    case ETH_P_IPV6:
        return false;
    case ETH_P_PAE:
        return false;
    default:
        printf("Ethernet protocol: 0x%x\n", ntohs(eth_header->h_proto));
        return false;
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
void handle_arp(unsigned char *buffer, struct arp_info *info)
{
    struct ether_arp *arp_header;

    arp_header = (struct ether_arp *) buffer;

    /* sender protocol address */
    if (inet_ntop(AF_INET, &arp_header->arp_spa, info->sip, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }

    /* target protocol address */
    if (inet_ntop(AF_INET, &arp_header->arp_tpa, info->tip, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }

    /* sender/target hardware address */
    snprintf(info->sha, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
             arp_header->arp_sha[2], arp_header->arp_sha[4], arp_header->arp_sha[5]);
    snprintf(info->tha, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
             arp_header->arp_tha[2], arp_header->arp_tha[4], arp_header->arp_tha[5]);

    info->op = ntohs(arp_header->arp_op); /* arp opcode (command) */
    info->ht = ntohs(arp_header->arp_hrd);
    info->pt = ntohs(arp_header->arp_pro);
    info->hs = arp_header->arp_hln;
    info->ps = arp_header->arp_pln;
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
void handle_ip(unsigned char *buffer, struct ip_info *info)
{
    struct iphdr *ip;
    int header_len;

    ip = (struct iphdr *) buffer;
    if (inet_ntop(AF_INET, &ip->saddr, info->src, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
    if (inet_ntop(AF_INET, &ip->daddr, info->dst, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
    info->protocol = ip->protocol;
    header_len = ip->ihl * 4;

    switch (ip->protocol) {
    case IPPROTO_ICMP:
        handle_icmp(buffer + header_len, info);
        break;
    case IPPROTO_IGMP:
        handle_igmp(buffer + header_len, info);
        break;
    case IPPROTO_TCP:
        handle_tcp(buffer + header_len, info);
        break;
    case IPPROTO_UDP:
        handle_udp(buffer + header_len, info);
        break;
    }
}

/*
 * ICMP message format:
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             unused                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Internet Header + 64 bits of Original Data Datagram      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The ICMP header is 8 bytes.
 */
void handle_icmp(unsigned char *buffer, struct ip_info *info)
{
    struct icmphdr *icmp = (struct icmphdr *) buffer;

    info->icmp.type = icmp->type;
    info->icmp.code = icmp->code;
    info->icmp.checksum = htons(info->icmp.checksum);
    if (icmp->type == ICMP_ECHOREPLY || icmp->type == ICMP_ECHO) {
        info->icmp.echo.id = ntohs(icmp->un.echo.id);
        info->icmp.echo.seq_num = ntohs(icmp->un.echo.sequence);
    }
}

/*
 * IGMP message format:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Type     | Max Resp Time |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Group Address                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Messages must be atleast 8 bytes.
 *
 * Message Type                  Destination Group
 * ------------                  -----------------
 * General Query                 All hosts (224.0.0.1)
 * Group-Specific Query          The group being queried
 * Membership Report             The group being reported
 * Leave Message                 All routers (224.0.0.2)
 *
 * 224.0.0.22 is the IGMPv3 multicast address.
 *
 * Max Resp Time specifies the maximum allowed time before sending a responding
 * report in units of 1/10 seconds. It is only meaningful in membership queries.
 * Default: 100 (10 seconds).
 *
 * Message query:
 * - A general query has group address field 0 and is sent to the all hosts
 *   multicast group (224.0.0.1)
 * - A group specific query must have a valid multicast group address
 * - The Query Interval is the interval between general queries sent by the
 *   querier. Default: 125 seconds.
 *
 * TODO: Handle IGMPv3 membership query
 */
void handle_igmp(unsigned char *buffer, struct ip_info *info)
{
    struct igmphdr *igmp;

    igmp = (struct igmphdr *) buffer;
    info->igmp.type = igmp->type;
    info->igmp.max_resp_time = igmp->code;
    info->igmp.checksum = ntohs(igmp->csum);
    if (inet_ntop(AF_INET, &igmp->group, info->igmp.group_addr,
                  INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
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
bool handle_udp(unsigned char *buffer, struct ip_info *info)
{
    struct udphdr *udp;

    udp = (struct udphdr *) buffer;
    info->udp.src_port = ntohs(udp->source);
    info->udp.dst_port = ntohs(udp->dest);
    info->udp.len = ntohs(udp->len);
    info->udp.checksum = ntohs(udp->check);

    for (int i = 0; i < 2; i++) {
        info->udp.data.utype = *((uint16_t *) &info->udp + i);
        if (check_port(buffer + UDP_HDRLEN, &info->udp.data, info->udp.data.utype, info->udp.len - UDP_HDRLEN))
            return true;
    }
    info->udp.data.utype = 0; /* port not handled */
    return false;
}

/*
 * TCP header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data | Res |N|C|E|U|A|P|R|S|F|                               |
 * | Offset|     |S|W|C|R|C|S|S|Y|I|            Window             |
 * |       |     | |R|E|G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Sequence Number: The sequence number of the first data octet in this segment (except
 *                  when SYN is present). If SYN is present the sequence number is the
 *                  initial sequence number (ISN) and the first data octet is ISN+1.
 * Ack Number: If the ACK control bit is set this field contains the value of the
 *             next sequence number the sender of the segment is expecting to
 *             receive. Once a connection is established this is always sent.
 * Data Offset: The number of 32 bits words in the TCP header. This indicates where the
 *               data begins.
 * Res: Reserved. Must be zero.
 * Control bits:
 *
 * NS: ECN-nonce concealment protection (experimental: see RFC 3540)
 * CWR: Congestion Window Reduced (CWR) flag is set by the sending host to
 *      indicate that it received a TCP segment with the ECE flag set and had
 *      responded in congestion control mechanism (added to header by RFC 3168).
 * ECE: ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
 *      If the SYN flag is set (1), that the TCP peer is ECN capable.
 *      If the SYN flag is clear (0), that a packet with Congestion Experienced flag set
 *      (ECN=11) in IP header received during normal transmission (added to header by
 *      RFC 3168).
 * URG: Urgent Pointer field significant
 * ACK: Acknowledgment field significant
 * PSH: Push Function
 * RST: Reset the connection
 * SYN: Synchronize sequence numbers
 * FIN: No more data from sender
 *
 * Window: The number of data octets beginning with the one indicated in the
 *         acknowledgment field which the sender of this segment is willing to accept.
 * Checksum: The checksum field is the 16 bit one's complement of the one's
 *           complement sum of all 16 bit words in the header and text.
 * Urgent Pointer: This field communicates the current value of the urgent pointer as a
 *            positive offset from the sequence number in this segment. The
 *            urgent pointer points to the sequence number of the octet following
 *            the urgent data. This field is only be interpreted in segments with
 *            the URG control bit set.
 */
bool handle_tcp(unsigned char *buffer, struct ip_info *info)
{
    struct tcphdr *tcp;

    tcp = (struct tcphdr *) buffer;
    info->tcp.src_port = ntohs(tcp->source);
    info->tcp.dst_port = ntohs(tcp->dest);
    info->tcp.seq_num = ntohl(tcp->seq);
    info->tcp.ack_num = ntohl(tcp->ack_seq);
    info->tcp.offset = tcp->doff;
    info->tcp.urg = tcp->urg;
    info->tcp.ack = tcp->ack;
    info->tcp.psh = tcp->psh;
    info->tcp.rst = tcp->rst;
    info->tcp.syn = tcp->syn;
    info->tcp.fin = tcp->fin;
    info->tcp.window = ntohs(tcp->window);
    info->tcp.checksum = ntohs(tcp->check);
    info->tcp.urg_ptr = ntohs(tcp->urg_ptr);

    for (int i = 0; i < 2; i++) {
        info->tcp.data.utype = *((uint16_t *) &info->tcp + i);
        if (check_port(buffer + info->tcp.offset / 4, &info->tcp.data, info->tcp.data.utype, 0))
            return true;
    }
    info->tcp.data.utype = 0; /* port not handled */
    return false;
}

bool check_port(unsigned char *buffer, struct application_info *info, uint16_t port, uint16_t packet_len)
{
    switch (port) {
    case DNS:
        return handle_dns(buffer, info);
    case NBNS:
        return handle_nbns(buffer, info);
    case SSDP:
        return handle_ssdp(buffer, info, packet_len);
    case HTTP:
        return handle_http(buffer, info);
    default:
        return false;
    }
}

/*
 * Handle DNS messages. Will return false if not DNS.
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
 * TODO: Handle authority and additional records.
 */
bool handle_dns(unsigned char *buffer, struct application_info *info)
{
    unsigned char *ptr = buffer;

    // TODO: Handle more than one question
    if ((ptr[4] << 8 | ptr[5]) != 0x1) { /* the QDCOUNT will in practice always be one */
        return false;
    }

    info->dns = malloc(sizeof(struct dns_info));
    info->dns->id = ptr[0] << 8 | ptr[1];
    info->dns->qr = (ptr[2] & 0x80) >> 7;
    info->dns->opcode = ptr[2] & 0x78;
    info->dns->aa = ptr[2] & 0x04;
    info->dns->tc = ptr[2] & 0x02;
    info->dns->rd = ptr[2] & 0x01;
    info->dns->ra = ptr[3] & 0x80;
    info->dns->rcode = ptr[3] & 0x0f;
    for (int i = 0, j = 4; i < 4; i++, j += 2) {
        info->dns->section_count[i] = ptr[j] << 8 | ptr[j + 1];
    }

    if (info->dns->qr) { /* DNS response */
        ptr += DNS_HDRLEN;

        /* QUESTION section */
        ptr += parse_dns_name(buffer, ptr, info->dns->question.qname);
        info->dns->question.qtype = ptr[0] << 8 | ptr[1];
        info->dns->question.qclass = ptr[2] << 8 | ptr[3];
        ptr += 4; /* skip qtype and qclass */

        /* Answer/Authority/Additional records sections */
        int num_records = 0;

        for (int i = ANCOUNT; i < 4; i++) {
            num_records += info->dns->section_count[i];
        }
        info->dns->record = malloc(num_records * sizeof(struct dns_resource_record));
        for (int i = 0; i < num_records; i++) {
            parse_dns_record(i, buffer, &ptr, info->dns);
        }
    } else { /* DNS query */
        if (info->dns->rcode != 0) { /* RCODE will be zero */
            free(info->dns);
            return false;
        }
        /* ANCOUNT and NSCOUNT values are zero */
        if (info->dns->section_count[ANCOUNT] != 0 && info->dns->section_count[NSCOUNT] != 0) {
            free(info->dns);
            return false;
        }
        /*
         * ARCOUNT will typically be 0, 1, or 2, depending on whether EDNS0
         * (RFC 2671) or TSIG (RFC 2845) are used
         */
        if (info->dns->section_count[ARCOUNT] > 2) {
            free(info->dns);
            return false;
        }
        ptr += DNS_HDRLEN;

        /* QUESTION section */
        ptr += parse_dns_name(buffer, ptr, info->dns->question.qname);
        info->dns->question.qtype = ptr[0] << 8 | ptr[1];
        info->dns->question.qclass = ptr[2] << 8 | ptr[3];

        /* Additional records */
        if (info->dns->section_count[ARCOUNT]) {
            info->dns->record = malloc(info->dns->section_count[ARCOUNT] *
                                           sizeof(struct dns_resource_record));
            for (int i = 0; i < info->dns->section_count[ARCOUNT]; i++) {
                parse_dns_record(i, buffer, &ptr, info->dns);
            }
        } else {
            info->dns->record = NULL;
        }
    }
    return true;
}

/*
 * A domain name in a message can be represented as:
 *
 * - a sequence of labels ending in a zero octet
 * - a pointer
 * - a sequence of labels ending with a pointer
 *
 * Each label is represented as a one octet length field followed by that number
 * of octets. The high order two bits of the length field must be zero.
 */
int parse_dns_name(unsigned char *buffer, unsigned char *ptr, char name[])
{
    unsigned int n = 0; /* total length of name entry */
    unsigned int label_length = ptr[0];
    bool compression = false;
    unsigned int name_ptr_len = 0;

    if (!label_length) return 1; /* length octet */

    while (label_length) {
        /*
         * The max size of a label is 63 bytes, so a length with the first 2 bits
         * set to 11 indicates that the label is a pointer to a prior occurrence
         * of the same name. The pointer is an offset from the beginnng of the
         * DNS message, i.e. the ID field of the header.
         *
         * The pointer takes the form of a two octet sequence:
         *
         * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         * | 1  1|                OFFSET                   |
         * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         */
        if (label_length & 0xc0) {
            uint16_t offset = (ptr[0] & 0x3f) << 8 | ptr[1];

            label_length = buffer[offset];
            memcpy(name + n, buffer + offset + 1, label_length);
            ptr = buffer + offset; /* ptr will point to start of label */

            /*
             * Only update name_ptr_len if this is the first pointer encountered.
             * name_ptr_len must not include the ptrs in the prior occurrence of
             * the same name, i.e. if the name is a pointer to a sequence of
             * labeles ending in a pointer.
             */
            if (!compression) {
                /*
                 * Total length of the name entry encountered so far + ptr. If name
                 * is just a pointer, n will be 0
                 */
                name_ptr_len = n + DNS_PTR_LEN;
            }
            compression = true;
        } else {
            memcpy(name + n, ptr + 1, label_length);
        }
        n += label_length;
        name[n++] = '.';
        ptr += label_length + 1; /* skip length octet + rest of label */
        label_length = ptr[0];
    }
    name[n - 1] = '\0';
    n++; /* add null label */
    return compression ? name_ptr_len : n;
}

/*
 * Parse a DNS resource record.
 * int i is the recource record index.
 */
void parse_dns_record(int i, unsigned char *buffer, unsigned char **ptr, struct dns_info *dns)
{
    uint16_t rdlen;

    *ptr += parse_dns_name(buffer, *ptr, dns->record[i].name);
    dns->record[i].type = (*ptr)[0] << 8 | (*ptr)[1];
    dns->record[i].class = (*ptr)[2] << 8 | (*ptr)[3];
    dns->record[i].ttl = (*ptr)[4] << 24 | (*ptr)[5] << 16 | (*ptr)[6] << 8 | (*ptr)[7];
    rdlen = (*ptr)[8] << 8 | (*ptr)[9];
    *ptr += 10; /* skip to rdata field */
    if (dns->record[i].class == DNS_CLASS_IN) {
        switch (dns->record[i].type) {
        case DNS_TYPE_A:
            if (rdlen == 4) {
                dns->record[i].rdata.address = (*ptr)[0] << 24 | (*ptr)[1] << 16 | (*ptr)[2] << 8 | (*ptr)[3];
            }
            *ptr += rdlen;
            break;
        case DNS_TYPE_NS:
            *ptr += parse_dns_name(buffer, *ptr, dns->record[i].rdata.nsdname);
        case DNS_TYPE_CNAME:
            *ptr += parse_dns_name(buffer, *ptr, dns->record[i].rdata.cname);
            break;
        case DNS_TYPE_SOA:
            *ptr += parse_dns_name(buffer, *ptr, dns->record[i].rdata.soa.mname);
            *ptr += parse_dns_name(buffer, *ptr, dns->record[i].rdata.soa.rname);
            dns->record[i].rdata.soa.serial = (*ptr)[0] << 24 | (*ptr)[1] << 16 | (*ptr)[2] << 8 | (*ptr)[3];
            dns->record[i].rdata.soa.retry = (*ptr)[4] << 24 | (*ptr)[5] << 16 | (*ptr)[6] << 8 | (*ptr)[7];
            dns->record[i].rdata.soa.expire = (*ptr)[8] << 24 | (*ptr)[9] << 16 | (*ptr)[10] << 8 | (*ptr)[11];
            dns->record[i].rdata.soa.minimum = (*ptr)[12] << 24 | (*ptr)[13] << 16 | (*ptr)[14] << 8 | (*ptr)[15];
            *ptr += 16;
            break;
        case DNS_TYPE_PTR:
            *ptr += parse_dns_name(buffer, *ptr, dns->record[i].rdata.ptrdname);
            break;
        case DNS_TYPE_AAAA:
            if (rdlen == 16) {
                for (int j = 0; j < rdlen; j++) {
                    dns->record[i].rdata.ipv6addr[j] = (*ptr)[j];
                }
            }
            *ptr += rdlen;
            break;
        default:
            *ptr += rdlen;
            break;
        }
    } else {
        *ptr += rdlen;
    }
}

/*
 * NBNS serves much of the same purpose as DNS, and the NetBIOS Name Service
 * packets follow the packet structure defined in DNS.
 *
 * NBNS header:
 *
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         NAME_TRN_ID           | OPCODE  |   NM_FLAGS  | RCODE |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          QDCOUNT              |           ANCOUNT             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          NSCOUNT              |           ARCOUNT             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * NM_FLAGS:
 *
 *   0   1   2   3   4   5   6
 * +---+---+---+---+---+---+---+
 * |AA |TC |RD |RA | 0 | 0 | B |
 * +---+---+---+---+---+---+---+
 */
bool handle_nbns(unsigned char *buffer, struct application_info *info)
{
    unsigned char *ptr = buffer;

    info->nbns = malloc(sizeof(struct nbns_info));
    info->nbns->id = ptr[0] << 8 | ptr[1];
    info->nbns->opcode = ptr[2] & 0x78;
    info->nbns->aa = ptr[2] & 0x04;
    info->nbns->tc = ptr[2] & 0x02;
    info->nbns->rd = ptr[2] & 0x01;
    info->nbns->ra = ptr[3] & 0x80;
    info->nbns->broadcast = ptr[3] & 0x10;
    info->nbns->rcode = ptr[3] & 0x0f;
    for (int i = 0, j = 4; i < 4; i++, j += 2) {
        info->nbns->section_count[i] = ptr[j] << 8 | ptr[j + 1];
    }

    /*
     * the first bit in the opcode field specifies whether it is a request (0)
     * or a response (1)
     */
    info->nbns->r = (ptr[2] & 0x80U) >> 7;

    if (info->nbns->r) { /* response */
        if (info->nbns->section_count[QDCOUNT] != 0) { /* QDCOUNT is always 0 for responses */
            free(info->nbns);
            return false;
        }
        ptr += DNS_HDRLEN;

        /* Answer/Authority/Additional records sections */
        int i = ANCOUNT;
        int num_records = 0;
        while (i < 4) {
            num_records += info->nbns->section_count[i++];
        }
        info->nbns->record = malloc(num_records * sizeof(struct nbns_rr));
        for (int j = 0; j < num_records; j++) {
            parse_nbns_record(j, buffer, &ptr, info->nbns);
        }
    } else { /* request */
        if (info->nbns->aa) { /* authoritative answer is only to be set in responses */
            free(info->nbns);
            return false;
        }
        if (info->nbns->section_count[QDCOUNT] == 0) { /* QDCOUNT must be non-zero for requests */
            free(info->nbns);
            return false;
        }
        ptr += DNS_HDRLEN;

        /* QUESTION section */
        char name[DNS_NAMELEN];
        ptr += parse_dns_name(buffer, ptr, name);
        decode_nbns_name(info->nbns->question.qname, name);
        info->nbns->question.qtype = ptr[0] << 8 | ptr[1];
        info->nbns->question.qclass = ptr[2] << 8 | ptr[3];
        ptr += 4; /* skip qtype and qclass */

        /* Additional records section */
        if (info->nbns->section_count[ARCOUNT]) {
            info->nbns->record = malloc(sizeof(struct nbns_rr));
            parse_nbns_record(0, buffer, &ptr, info->nbns);
        } else {
            info->nbns->record = NULL;
        }
    }

    return true;
}

/*
 * The 16 byte NetBIOS name is mapped into a 32 byte wide field using a
 * reversible, half-ASCII, biased encoding, cf. RFC 1001, First-level encoding
 */
void decode_nbns_name(char *dest, char *src)
{
    for (int i = 0; i < 16; i++) {
        dest[i] = (src[2*i] - 'A') << 4 | (src[2*i + 1] - 'A');
    }
    // TODO: Fix this properly
    int c = 14;
    while (c && isspace(dest[c])) { /* remove trailing whitespaces */
        c--;
    }
    dest[c + 1] = '\0';
}

/*
 * Parse a NBNS resource record.
 * int i is the resource record index.
 */
void parse_nbns_record(int i, unsigned char *buffer, unsigned char **ptr, struct nbns_info *nbns)
{
    int rdlen;
    char name[DNS_NAMELEN];

    *ptr += parse_dns_name(buffer, *ptr, name);
    decode_nbns_name(nbns->record[i].rrname, name);
    nbns->record[i].rrtype = (*ptr)[0] << 8 | (*ptr)[1];
    nbns->record[i].rrclass = (*ptr)[2] << 8 | (*ptr)[3];
    nbns->record[i].ttl = (*ptr)[4] << 24 | (*ptr)[5] << 16 | (*ptr)[6] << 8 | (*ptr)[7];
    rdlen = (*ptr)[8] << 8 | (*ptr)[9];
    *ptr += 10; /* skip to rdata field */

    switch (nbns->record[i].rrtype) {
    case NBNS_NB:
        if (rdlen >= 6) {
            nbns->record[i].rdata.nb.g = (*ptr)[0] & 0x80U;
            nbns->record[i].rdata.nb.ont = (*ptr)[0] & 0x60;
            rdlen -= 2;
            (*ptr) += 2;
            for (int j = 0, k = 0; k < rdlen && k < MAX_NBNS_ADDR * 4 ; j++, k += 4) {
                nbns->record[i].rdata.nb.address[j] =
                    (*ptr)[k] << 24 | (*ptr)[k + 1] << 16 | (*ptr)[k + 2] << 8 | (*ptr)[k + 3];
            }
            nbns->record[i].rdata.nb.num_addr = rdlen / 4;
        }
        *ptr += rdlen;
        break;
    case NBNS_NS:
    {
        char name[DNS_NAMELEN];

        *ptr += parse_dns_name(buffer, *ptr, name);
        decode_nbns_name(nbns->record[i].rdata.nsdname, name);
        break;
    }
    case NBNS_A:
        if (rdlen == 4) {
            nbns->record[i].rdata.nsdipaddr =
                (*ptr)[0] << 24 | (*ptr)[1] << 16 | (*ptr)[2] << 8 | (*ptr)[3];
        }
        *ptr += rdlen;
        break;
    case NBNS_NBSTAT:
    {
        uint8_t num_names;

        num_names = (*ptr)[0];
        (*ptr)++;
        for (int j = 0; j < num_names; j++) {
            memcpy(nbns->record[i].rdata.nbstat[j].node_name, (*ptr), NBNS_NAMELEN);
            nbns->record[i].rdata.nbstat[j].node_name[NBNS_NAMELEN] = '\0';
            *ptr += NBNS_NAMELEN;
            nbns->record[i].rdata.nbstat[j].name_flags = (*ptr)[0] << 8 | (*ptr)[1];
            *ptr += 2;
        }
        // TODO: Include statistics
        break;
    }
    case NBNS_NULL:
    default:
        *ptr += rdlen;
        break;
    }
}

/*
 * The Simple Service Discovery Protocol (SSDP) is a network protocol based on
 * the Internet Protocol Suite for advertisement and discovery of network
 * services and presence information. It is a text-based protocol based on HTTPU.
 * Services are announced by the hosting system with multicast addressing to a
 * specifically designated IP multicast address at UDP port number 1900.
 *
 * SSDP uses a NOTIFY HTTP method to announce the establishment or withdrawal of
 * services (presence) information to the multicast group. A client that wishes
 * to discover available services on a network uses the M-SEARCH method.
 * Responses to such search requests are sent via unicast addressing to the
 * originating address and port number of the multicast request.
 *
 */
bool handle_ssdp(unsigned char *buffer, struct application_info *info, uint16_t len)
{
    list_t *ssdp_fields;

    ssdp_fields = list_init(NULL);
    parse_ssdp((char *) buffer, len, &ssdp_fields);
    info->ssdp = ssdp_fields;
    return true;
}

/*
 * Parses an SSDP string.
 *
 * Adds the SSDP message header fields to msg_header list
 */
void parse_ssdp(char *str, int n, list_t **msg_header)
{
    char *token;
    char cstr[n];

    strncpy(cstr, str, n);
    token = strtok(cstr, "\r\n");
    while (token) {
        int len;
        char *field;

        len = strlen(token);
        field = malloc(len + 1);
        strncpy(field, token, len);
        field[len] = '\0';
        *msg_header = list_push_back(*msg_header, field);
        token = strtok(NULL, "\r\n");
    }
}

bool handle_http(unsigned char *buffer, struct application_info *info)
{
    return false;
}
