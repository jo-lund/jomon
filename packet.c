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
#include "packet.h"
#include "misc.h"
#include "error.h"

#define DNS_PTR_LEN 2

static void handle_arp(unsigned char *buffer, struct arp_info *info);
static void handle_ip(unsigned char *buffer, struct ip_info *info);
static void handle_icmp(unsigned char *buffer, struct ip_info *info);
static void handle_igmp(unsigned char *buffer, struct ip_info *info);
static void handle_tcp(unsigned char *buffer, struct ip_info *info);
static void handle_udp(unsigned char *buffer, struct ip_info *info);
static bool handle_dns(unsigned char *buffer, struct ip_info *info);
static bool handle_nbns(unsigned char *buffer, struct ip_info *info);
static bool handle_ssdp(unsigned char *buffer, struct ip_info *info);
static int parse_dns_name(unsigned char *buffer, unsigned char *ptr, char name[]);
static void parse_dns_record(int i, unsigned char *buffer, unsigned char **ptr, struct ip_info *info);
static void decode_nbns_name(char *dest, char *src);
static void parse_nbns_record(int i, unsigned char *buffer, unsigned char **ptr, struct ip_info *info);
static void check_address(unsigned char *buffer);
static bool check_port(unsigned char *buffer, struct ip_info *info, uint16_t port);

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

    if (p->ut == IPv4) {
        switch (p->ip.protocol) {
        case IPPROTO_UDP:
            switch (p->ip.udp.utype) {
            case DNS:
                if (p->ip.udp.dns->record) {
                    free(p->ip.udp.dns->record);
                }
                free(p->ip.udp.dns);
                break;
            case NBNS:
                if (p->ip.udp.nbns->record) {
                    free(p->ip.udp.nbns->record);
                }
                free(p->ip.udp.nbns);
                break;
            case SSDP:
                free(p->ip.udp.ssdp->str);
                free(p->ip.udp.ssdp);
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }
    }
    free(p);
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
        p->ut = IPv4;
        return true;
    }
    case ETH_P_ARP:
    {
        handle_arp(buffer + ETH_HLEN, &p->arp);
        p->ut = ARP;
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
void handle_udp(unsigned char *buffer, struct ip_info *info)
{
    struct udphdr *udp;
    bool valid = false;

    udp = (struct udphdr *) buffer;
    info->udp.src_port = ntohs(udp->source);
    info->udp.dst_port = ntohs(udp->dest);
    info->udp.len = ntohs(udp->len);

    for (int i = 0; i < 2 && !valid; i++) {
        info->udp.utype = *((uint16_t *) &info->udp + i);
        valid = check_port(buffer + UDP_HDRLEN, info, info->udp.utype);
    }
}

bool check_port(unsigned char *buffer, struct ip_info *info, uint16_t port)
{
    switch (port) {
    case DNS:
        return handle_dns(buffer, info);
    case NBNS:
        return handle_nbns(buffer, info);
    case SSDP:
        return handle_ssdp(buffer, info);
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
bool handle_dns(unsigned char *buffer, struct ip_info *info)
{
    unsigned char *ptr = buffer;

    /*
     * UDP header length (8 bytes) + DNS header length (12 bytes).
     * DNS Messages carried by UDP are restricted to 512 bytes (not counting the 
     * UDP header.
     */
    if (info->udp.len < 20 || info->udp.len > 520) {
        return false;
    }

    // TODO: Handle more than one question
    if ((ptr[4] << 8 | ptr[5]) != 0x1) { /* the QDCOUNT will in practice always be one */
        return false;
    }
    info->udp.dns = malloc(sizeof(struct dns_info));
    info->udp.dns->id = ptr[0] << 8 | ptr[1];
    info->udp.dns->qr = (ptr[2] & 0x80) >> 7;
    info->udp.dns->opcode = ptr[2] & 0x78;
    info->udp.dns->aa = ptr[2] & 0x04;
    info->udp.dns->tc = ptr[2] & 0x02;
    info->udp.dns->rd = ptr[2] & 0x01;
    info->udp.dns->ra = ptr[3] & 0x80;
    info->udp.dns->rcode = ptr[3] & 0x0f;
    for (int i = 0, j = 4; i < 4; i++, j += 2) {
        info->udp.dns->section_count[i] = ptr[j] << 8 | ptr[j + 1];
    }

    if (info->udp.dns->qr) { /* DNS response */
        ptr += DNS_HDRLEN;

        /* QUESTION section */
        ptr += parse_dns_name(buffer, ptr, info->udp.dns->question.qname);
        info->udp.dns->question.qtype = ptr[0] << 8 | ptr[1];
        info->udp.dns->question.qclass = ptr[2] << 8 | ptr[3];
        ptr += 4; /* skip qtype and qclass */

        /* Answer/Authority/Additional records sections */
        int num_records = 0;

        for (int i = ANCOUNT; i < 4; i++) {
            num_records += info->udp.dns->section_count[i];
        }
        info->udp.dns->record = malloc(num_records * sizeof(struct dns_resource_record));
        for (int i = 0; i < num_records; i++) {
            parse_dns_record(i, buffer, &ptr, info);
        }
    } else { /* DNS query */
        if (info->udp.dns->rcode != 0) { /* RCODE will be zero */
            return false;
        }
        /* ANCOUNT and NSCOUNT values are zero */
        if (info->udp.dns->section_count[ANCOUNT] != 0 && info->udp.dns->section_count[NSCOUNT] != 0) {
            return false;
        }
        /*
         * ARCOUNT will typically be 0, 1, or 2, depending on whether EDNS0
         * (RFC 2671) or TSIG (RFC 2845) are used
         */
        if (info->udp.dns->section_count[ARCOUNT] > 2) {
            return false;
        }
        ptr += DNS_HDRLEN;

        /* QUESTION section */
        ptr += parse_dns_name(buffer, ptr, info->udp.dns->question.qname);
        info->udp.dns->question.qtype = ptr[0] << 8 | ptr[1];
        info->udp.dns->question.qclass = ptr[2] << 8 | ptr[3];

        /* Additional records */
        if (info->udp.dns->section_count[ARCOUNT]) {
            info->udp.dns->record = malloc(info->udp.dns->section_count[ARCOUNT] *
                                           sizeof(struct dns_resource_record));
            for (int i = 0; i < info->udp.dns->section_count[ARCOUNT]; i++) {
                parse_dns_record(i, buffer, &ptr, info);
            }
        } else {
            info->udp.dns->record = NULL;
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
void parse_dns_record(int i, unsigned char *buffer, unsigned char **ptr, struct ip_info *info)
{
    uint16_t rdlen;

    *ptr += parse_dns_name(buffer, *ptr, info->udp.dns->record[i].name);
    info->udp.dns->record[i].type = (*ptr)[0] << 8 | (*ptr)[1];
    info->udp.dns->record[i].class = (*ptr)[2] << 8 | (*ptr)[3];
    info->udp.dns->record[i].ttl = (*ptr)[4] << 24 | (*ptr)[5] << 16 | (*ptr)[6] << 8 | (*ptr)[7];
    rdlen = (*ptr)[8] << 8 | (*ptr)[9];
    *ptr += 10; /* skip to rdata field */
    if (info->udp.dns->record[i].class == DNS_CLASS_IN) {
        switch (info->udp.dns->record[i].type) {
        case DNS_TYPE_A:
            if (rdlen == 4) {
                info->udp.dns->record[i].rdata.address = (*ptr)[0] << 24 | (*ptr)[1] << 16 | (*ptr)[2] << 8 | (*ptr)[3];
            }
            *ptr += rdlen;
            break;
        case DNS_TYPE_NS:
            *ptr += parse_dns_name(buffer, *ptr, info->udp.dns->record[i].rdata.nsdname);
        case DNS_TYPE_CNAME:
            *ptr += parse_dns_name(buffer, *ptr, info->udp.dns->record[i].rdata.cname);
            break;
        case DNS_TYPE_SOA:
            *ptr += parse_dns_name(buffer, *ptr, info->udp.dns->record[i].rdata.soa.mname);
            *ptr += parse_dns_name(buffer, *ptr, info->udp.dns->record[i].rdata.soa.rname);
            info->udp.dns->record[i].rdata.soa.serial = (*ptr)[0] << 24 | (*ptr)[1] << 16 | (*ptr)[2] << 8 | (*ptr)[3];
            info->udp.dns->record[i].rdata.soa.retry = (*ptr)[4] << 24 | (*ptr)[5] << 16 | (*ptr)[6] << 8 | (*ptr)[7];
            info->udp.dns->record[i].rdata.soa.expire = (*ptr)[8] << 24 | (*ptr)[9] << 16 | (*ptr)[10] << 8 | (*ptr)[11];
            info->udp.dns->record[i].rdata.soa.minimum = (*ptr)[12] << 24 | (*ptr)[13] << 16 | (*ptr)[14] << 8 | (*ptr)[15];
            *ptr += 16;
            break;
        case DNS_TYPE_PTR:
            *ptr += parse_dns_name(buffer, *ptr, info->udp.dns->record[i].rdata.ptrdname);
            break;
        case DNS_TYPE_AAAA:
            if (rdlen == 16) {
                for (int j = 0; j < rdlen; j++) {
                    info->udp.dns->record[i].rdata.ipv6addr[j] = (*ptr)[j];
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
bool handle_nbns(unsigned char *buffer, struct ip_info *info)
{
    /* max packet length for UDP is 576 */
    if (info->udp.len > 576) {
        return false;
    }
    unsigned char *ptr = buffer;

    info->udp.nbns = malloc(sizeof(struct nbns_info));
    info->udp.nbns->id = ptr[0] << 8 | ptr[1];
    info->udp.nbns->opcode = ptr[2] & 0x78;
    info->udp.nbns->aa = ptr[2] & 0x04;
    info->udp.nbns->tc = ptr[2] & 0x02;
    info->udp.nbns->rd = ptr[2] & 0x01;
    info->udp.nbns->ra = ptr[3] & 0x80;
    info->udp.nbns->broadcast = ptr[3] & 0x10;
    info->udp.nbns->rcode = ptr[3] & 0x0f;
    for (int i = 0, j = 4; i < 4; i++, j += 2) {
        info->udp.nbns->section_count[i] = ptr[j] << 8 | ptr[j + 1];
    }

    /*
     * the first bit in the opcode field specifies whether it is a request (0)
     * or a response (1)
     */
    info->udp.nbns->r = (ptr[2] & 0x80U) >> 7;

    if (info->udp.nbns->r) { /* response */
        if (info->udp.nbns->section_count[QDCOUNT] != 0) { /* QDCOUNT is always 0 for responses */
            return false;
        }
        ptr += DNS_HDRLEN;

        /* Answer/Authority/Additional records sections */
        int i = ANCOUNT;
        int num_records = 0;
        while (i < 4) {
            num_records += info->udp.nbns->section_count[i++];
        }
        info->udp.nbns->record = malloc(num_records * sizeof(struct nbns_rr));
        for (int j = 0; j < num_records; j++) {
            parse_nbns_record(j, buffer, &ptr, info);
        }
    } else { /* request */
        if (info->udp.nbns->aa) { /* authoritative answer is only to be set in responses */
            return false;
        }
        if (info->udp.nbns->section_count[QDCOUNT] == 0) { /* QDCOUNT must be non-zero for requests */
            return false;
        }
        ptr += DNS_HDRLEN;

        /* QUESTION section */
        char name[DNS_NAMELEN];
        ptr += parse_dns_name(buffer, ptr, name);
        decode_nbns_name(info->udp.nbns->question.qname, name);
        info->udp.nbns->question.qtype = ptr[0] << 8 | ptr[1];
        info->udp.nbns->question.qclass = ptr[2] << 8 | ptr[3];
        ptr += 4; /* skip qtype and qclass */

        /* Additional records section */
        if (info->udp.nbns->section_count[ARCOUNT]) {
            info->udp.nbns->record = malloc(sizeof(struct nbns_rr));
            parse_nbns_record(0, buffer, &ptr, info);
        } else {
            info->udp.nbns->record = NULL;
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
void parse_nbns_record(int i, unsigned char *buffer, unsigned char **ptr, struct ip_info *info)
{
    int rdlen;
    char name[DNS_NAMELEN];

    *ptr += parse_dns_name(buffer, *ptr, name);
    decode_nbns_name(info->udp.nbns->record[i].rrname, name);
    info->udp.nbns->record[i].rrtype = (*ptr)[0] << 8 | (*ptr)[1];
    info->udp.nbns->record[i].rrclass = (*ptr)[2] << 8 | (*ptr)[3];
    info->udp.nbns->record[i].ttl = (*ptr)[4] << 24 | (*ptr)[5] << 16 | (*ptr)[6] << 8 | (*ptr)[7];
    rdlen = (*ptr)[8] << 8 | (*ptr)[9];
    *ptr += 10; /* skip to rdata field */

    switch (info->udp.nbns->record[i].rrtype) {
    case NBNS_NB:
        if (rdlen >= 6) {
            info->udp.nbns->record[i].rdata.nb.g = (*ptr)[0] & 0x80U;
            info->udp.nbns->record[i].rdata.nb.ont = (*ptr)[0] & 0x60;
            rdlen -= 2;
            (*ptr) += 2;
            for (int j = 0, k = 0; k < rdlen && k < MAX_NBNS_ADDR * 4 ; j++, k += 4) {
                info->udp.nbns->record[i].rdata.nb.address[j] =
                    (*ptr)[k] << 24 | (*ptr)[k + 1] << 16 | (*ptr)[k + 2] << 8 | (*ptr)[k + 3];
            }
            info->udp.nbns->record[i].rdata.nb.num_addr = rdlen / 4;
        }
        *ptr += rdlen;
        break;
    case NBNS_NS:
    {
        char name[DNS_NAMELEN];

        *ptr += parse_dns_name(buffer, *ptr, name);
        decode_nbns_name(info->udp.nbns->record[i].rdata.nsdname, name);
        break;
    }
    case NBNS_A:
        if (rdlen == 4) {
            info->udp.nbns->record[i].rdata.nsdipaddr =
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
            memcpy(info->udp.nbns->record[i].rdata.nbstat[j].node_name, (*ptr), NBNS_NAMELEN);
            info->udp.nbns->record[i].rdata.nbstat[j].node_name[NBNS_NAMELEN] = '\0';
            *ptr += NBNS_NAMELEN;
            info->udp.nbns->record[i].rdata.nbstat[j].name_flags = (*ptr)[0] << 8 | (*ptr)[1];
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
bool handle_ssdp(unsigned char *buffer, struct ip_info *info)
{
    info->udp.ssdp = malloc(sizeof(struct ssdp_info));
    info->udp.ssdp->n = info->udp.len - UDP_HDRLEN;
    info->udp.ssdp->str = malloc(info->udp.ssdp->n);
    strncpy(info->udp.ssdp->str, buffer, info->udp.ssdp->n);

    return true;
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
    info->igmp.checksum = htons(igmp->csum);
    if (inet_ntop(AF_INET, &igmp->group, info->igmp.group_addr,
                  INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
}

void handle_tcp(unsigned char *buffer, struct ip_info *info)
{

}
