#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <ctype.h>
#include <netinet/tcp.h>
#include "../misc.h"
#include "../error.h"
#include "packet.h"

#define LLC_HDR_LEN 3
#define SNAP_HDR_LEN 5
#define UDP_HDR_LEN 8
#define MULTICAST_ADDR_MASK 0xe

static uint32_t packet_count = 0;

static bool check_port(unsigned char *buffer, struct application_info *info, uint16_t port,
                       uint16_t packet_len, bool *error);
static void free_protocol_data(struct application_info *info);
static bool handle_ethernet(unsigned char *buffer, int n, struct eth_info *eth);
static bool handle_ip(unsigned char *buffer, int n, struct eth_info *info);
static bool handle_tcp(unsigned char *buffer, int n, struct ip_info *info);
static bool handle_udp(unsigned char *buffer, int n, struct ip_info *info);

/* application layer protocol handlers */
static bool handle_ssdp(unsigned char *buffer, struct application_info *info, uint16_t len);
static void parse_ssdp(char *str, int n, list_t **msg_header);

size_t read_packet(int sockfd, unsigned char *buffer, size_t len, struct packet **p)
{
    int n;

    *p = calloc(1, sizeof(struct packet));
    if ((n = read(sockfd, buffer, len)) == -1) {
        free_packet(*p);
        err_sys("read error");
    }
    if (!handle_ethernet(buffer, n, &(*p)->eth)) {
        free_packet(*p);
        return 0;
    }
    (*p)->num = ++packet_count;
    return n;
}

bool decode_packet(unsigned char *buffer, size_t len, struct packet **p)
{
    *p = calloc(1, sizeof(struct packet));
    if (!handle_ethernet(buffer, len, &(*p)->eth)) {
        free_packet(p);
        return false;
    }
    (*p)->num = ++packet_count;
    return true;
}

void free_packet(void *data)
{
    struct packet *p = (struct packet *) data;

    if (p->eth.ethertype < ETH_P_802_3_MIN) {
        if (p->eth.llc->dsap == 0xaa && p->eth.llc->ssap == 0xaa) {
            if (p->eth.llc->snap->payload) {
                free(p->eth.llc->snap->payload);
            }
            free(p->eth.llc->snap);
        } else if (p->eth.llc->dsap == 0x42 && p->eth.llc->ssap == 0x42) {
            free(p->eth.llc->bpdu);
        } else if (p->eth.llc->payload_len) {
            free(p->eth.llc->payload);
        }
        free(p->eth.llc);
        return;
    }
    switch (p->eth.ethertype) {
    case ETH_P_IP:
        switch (p->eth.ip->protocol) {
        case IPPROTO_UDP:
            free_protocol_data(&p->eth.ip->udp.data);
            break;
        case IPPROTO_TCP:
            free_protocol_data(&p->eth.ip->tcp.data);
            break;
        default:
            if (p->eth.ip->payload_len) {
                free(p->eth.ip->payload);
            }
            break;
        }
        free(p->eth.ip);
        break;
    case ETH_P_ARP:
        free(p->eth.arp);
        break;
    default:
        if (p->eth.payload_len) {
            free(p->eth.payload);
        }
        break;
    }
    free(p);
}

void free_protocol_data(struct application_info *info)
{
    switch (info->utype) {
    case DNS:
        if (info->dns) {
            if (info->dns->record) {
                free(info->dns->record);
            }
            free(info->dns);
        }
        break;
    case NBNS:
        if (info->nbns) {
            if (info->nbns->record) {
                free(info->nbns->record);
            }
            free(info->nbns);
        }
        break;
    case SSDP:
        if (info->ssdp) {
            list_free(info->ssdp);
        }
        break;
    case HTTP:
        if (info->http) {
            if (info->http->start_line) {
                free(info->http->start_line);
            }
            if (info->http->header) {
                list_free(info->http->header);
            }
            if (info->http->data) {
                free(info->http->data);
            }
            free(info->http);
        }
        break;
    default:
        if (info->payload_len) {
            free(info->payload);
        }
        break;
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
 * FT, the frame type or EtherType, can be used for two different purposes.
 * Values of 1500 and below (Ethernet 802.3) mean that it is used to indicate
 * the size of the payload in bytes, while values of 1536 and above (Ethernet II)
 * indicate that it is used as an EtherType, to indicate which protocol is
 * encapsulated in the payload of the frame.
 *
 * There are several types of 802.3 frames, e.g. 802.2 LLC (Logical Link Control)
 * and 802.2 SNAP (Subnetwork Access Protocol).
 *
 * 802.2 LLC Header
 *
 *     1        1         1
 * +--------+--------+--------+
 * | DSAP=K1| SSAP=K1| Control|
 * +--------+--------+--------+
 *
 * 802.2 SNAP Header
 *
 * When SNAP extension is used, it is located right after the LLC header. The
 * payload start bytes for SNAP is 0xaaaa, which means the K1 value is 0xaa.
 * The control value is 3 (Unnumbered Information).
 *
 * +--------+--------+---------+--------+--------+
 * |Protocol Id or Org Code =K2|    EtherType    |
 * +--------+--------+---------+--------+--------+
 *
 * The K2 value is 0 (zero).
 */
bool handle_ethernet(unsigned char *buffer, int n, struct eth_info *eth)
{
    if (n < ETHERNET_HDRLEN) return false;

    struct ethhdr *eth_header;
    bool error = false;

    eth_header = (struct ethhdr *) buffer;
    memcpy(eth->mac_src, eth_header->h_source, ETH_ALEN);
    memcpy(eth->mac_dst, eth_header->h_dest, ETH_ALEN);
    eth->ethertype = ntohs(eth_header->h_proto);

    /* Ethernet 802.3 frame */
    if (eth->ethertype < ETH_P_802_3_MIN) {
        unsigned char *ptr;

        ptr = buffer + ETH_HLEN;
        eth->llc = calloc(1, sizeof(struct eth_802_llc));
        eth->llc->dsap = ptr[0];
        eth->llc->ssap = ptr[1];
        eth->llc->control = ptr[2];

        /* Spanning Tree Protocol */
        if (eth->llc->dsap == 0x42 && eth->llc->ssap == 0x42) {
            error = !handle_stp(ptr + LLC_HDR_LEN, eth->ethertype - LLC_HDR_LEN, eth->llc);
        } else if (eth->llc->dsap == 0xaa && eth->llc->ssap == 0xaa) {
            /* SNAP extension */
            eth->llc->snap = malloc(sizeof(struct snap_info));
            ptr += LLC_HDR_LEN;
            memcpy(eth->llc->snap->oui, ptr, 3);
            ptr += 3; /* skip first 3 bytes of 802.2 SNAP */
            eth->llc->snap->protocol_id = ptr[0] << 8 | ptr[1];

            /* TODO: If OUI is 0 I need to to handle the internet protocols that
               will be layered on top of SNAP */
            ptr += 2;
            eth->llc->snap->payload_len = eth->ethertype - LLC_HDR_LEN - SNAP_HDR_LEN;
            eth->llc->snap->payload = malloc(eth->llc->snap->payload_len);
            memcpy(eth->llc->snap->payload, ptr, eth->llc->snap->payload_len);
        } else { /* not handled */
            eth->llc->payload_len = eth->ethertype - LLC_HDR_LEN;
            eth->llc->payload = malloc(eth->llc->payload_len);
            memcpy(eth->llc->payload, ptr, eth->llc->payload_len);
        }
    } else {
        switch (eth->ethertype) {
        case ETH_P_IP:
            error = !handle_ip(buffer + ETH_HLEN, n, eth);
            break;
        case ETH_P_ARP:
            error = !handle_arp(buffer + ETH_HLEN, n, eth);
            break;
        case ETH_P_IPV6:
        case ETH_P_PAE:
        default:
            //printf("Ethernet protocol: 0x%x\n", eth->ethertype);
            error = true;
            break;
        }
    }
    if (error) {
        eth->payload_len = n - ETH_HLEN;
        eth->payload = malloc(n - ETH_HLEN);
        memcpy(eth->payload, buffer + ETH_HLEN, n - ETH_HLEN);
    }
    return true;
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
 * Flags: Used to control and identify fragments
 *        Bit 0: Reserved, must be zero
 *        Bit 1: Don't Fragment (DF)
 *        Bit 2: More Fragments (MF)
 * Fragment offset: Specifies the offset of a particular fragment relative to
 * the beginning of the unfragmented IP datagram. The first fragment has an
 * offset of zero.
 * Protocol: Defines the protocol used in the data portion of the packet.
 */
bool handle_ip(unsigned char *buffer, int n, struct eth_info *eth)
{
    struct iphdr *ip;
    unsigned int header_len;
    bool error = false;

    ip = (struct iphdr *) buffer;

    if (n < ip->ihl * 4) return false;

    eth->ip = calloc(1, sizeof(struct ip_info));
    if (inet_ntop(AF_INET, &ip->saddr, eth->ip->src, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
    if (inet_ntop(AF_INET, &ip->daddr, eth->ip->dst, INET_ADDRSTRLEN) == NULL) {
        err_msg("inet_ntop error");
    }
    eth->ip->version = ip->version;
    eth->ip->ihl = ip->ihl;

    /* Originally defined as type of service, but now defined as differentiated
       services code point and explicit congestion control */
    eth->ip->dscp = (ip->tos & 0xfc) >> 2;
    eth->ip->ecn = ip->tos & 0x03;

    eth->ip->length = ntohs(ip->tot_len);
    eth->ip->id = ntohs(ip->id);
    eth->ip->foffset = ntohs(ip->frag_off);
    eth->ip->ttl = ip->ttl;
    eth->ip->protocol = ip->protocol;
    eth->ip->checksum = ntohs(ip->check);
    header_len = ip->ihl * 4;

    switch (ip->protocol) {
    case IPPROTO_ICMP:
        error = !handle_icmp(buffer + header_len, n, eth->ip);
        break;
    case IPPROTO_IGMP:
        error = !handle_igmp(buffer + header_len, n, eth->ip);
        break;
    case IPPROTO_TCP:
        error = !handle_tcp(buffer + header_len, n, eth->ip);
        break;
    case IPPROTO_UDP:
        error = !handle_udp(buffer + header_len, n, eth->ip);
        break;
    case IPPROTO_PIM:
    default:
        error = true;
        break;
    }
    if (error) {
        eth->ip->payload_len = n - header_len;
        eth->ip->payload = malloc(n - header_len);
        memcpy(eth->ip->payload, buffer + header_len, n - header_len);
    }
    return true;
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
bool handle_udp(unsigned char *buffer, int n, struct ip_info *info)
{
    if (n < UDP_HDR_LEN) return false;

    struct udphdr *udp;
    bool error;

    udp = (struct udphdr *) buffer;
    info->udp.src_port = ntohs(udp->source);
    info->udp.dst_port = ntohs(udp->dest);
    info->udp.len = ntohs(udp->len);
    info->udp.checksum = ntohs(udp->check);

    for (int i = 0; i < 2; i++) {
        info->udp.data.utype = *((uint16_t *) &info->udp + i);
        if (check_port(buffer + UDP_HDR_LEN, &info->udp.data, info->udp.data.utype,
                       info->udp.len - UDP_HDR_LEN, &error)) {
            return true;
        }
    }
    info->udp.data.utype = 0;

    /* unknown application payload data */
    if (info->udp.len - UDP_HDR_LEN > 0) {
        info->udp.data.payload = malloc(info->udp.len - UDP_HDR_LEN);
        info->udp.data.payload_len = info->udp.len - UDP_HDR_LEN;
        memcpy(info->udp.data.payload, buffer + UDP_HDR_LEN, info->udp.data.payload_len);
    }
    return true;
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
 *              data begins.
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
bool handle_tcp(unsigned char *buffer, int n, struct ip_info *info)
{
    struct tcphdr *tcp;
    bool error;
    uint16_t payload_len;

    tcp = (struct tcphdr *) buffer;
    if (n < tcp->doff * 4) return false;

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
    payload_len = info->length - info->ihl * 4 - info->tcp.offset * 4;

    /* only check port if there is a payload */
    if (payload_len > 0) {
        for (int i = 0; i < 2; i++) {
            info->tcp.data.utype = *((uint16_t *) &info->tcp + i);
            if (check_port(buffer + info->tcp.offset * 4, &info->tcp.data, info->tcp.data.utype,
                           info->length - info->ihl * 4, &error)) {
                return true;
            }
        }
    }
    info->tcp.data.utype = 0;

    /* unknown application payload data */
    if (payload_len > 0) {
        info->tcp.data.payload = malloc(payload_len);
        info->tcp.data.payload_len = payload_len;
        memcpy(info->tcp.data.payload, buffer + info->tcp.offset * 4, payload_len);
    }
    return true;
}

/*
 * Checks which well-known or registered port the packet originated from or is
 * addressed to. On error the error argument will be set to true, e.g. if
 * checksum correction is enabled and this calculation fails.
 *
 * Returns false if it's an ephemeral port, the port is not yet supported or in
 * case of errors in decoding the packet.
 */
bool check_port(unsigned char *buffer, struct application_info *info, uint16_t port,
                uint16_t packet_len, bool *error)
{
    switch (port) {
    case DNS:
        return handle_dns(buffer, info);
    case NBNS:
        return handle_nbns(buffer, info);
    case SSDP:
        return handle_ssdp(buffer, info, packet_len);
    /* case HTTP: */
    /*     *error = handle_http(buffer, info, packet_len); */
    /*     return true; */
    default:
        return false;
    }
}

/*
 * The Simple Service Discovery Protocol (SSDP) is a network protocol based on
 * the Internet Protocol Suite for advertisement and discovery of network
 * services and presence information. It is a text-based protocol based on HTTP.
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
 * Parses an SSDP string. SSDP strings are based on HTTP1.1 but contains no
 * message body.
 *
 * Copies the lines delimited by CRLF, i.e. the start line and the SSDP message
 * header fields, to msg_header list.
 */
void parse_ssdp(char *str, int n, list_t **msg_header)
{
    char *token;
    char cstr[n];

    strncpy(cstr, str, n);
    token = strtok(cstr, "\r\n");
    while (token) {
        char *field;

        field = strdup(token);
        *msg_header = list_push_back(*msg_header, field);
        token = strtok(NULL, "\r\n");
    }
}
