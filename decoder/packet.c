#define _GNU_SOURCE
#include <sys/uio.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ctype.h>
#include <sys/types.h>
#include "../misc.h"
#include "../error.h"
#include "packet.h"
#include "packet_dns.h"
#include "packet_nbns.h"
#include "packet_http.h"
#include "packet_stp.h"
#include "packet_arp.h"
#include "packet_ip.h"
#include "packet_ssdp.h"
#include "packet_nbds.h"
#include "packet_snmp.h"

/* this needs to be in the same order as enum protocols, see packet.h */
struct packet_statistics pstat[] = {
    { "Total", 0, 0 },
    { "ARP", 0, 0 },
    { "STP", 0, 0 },
    { "IPv4", 0, 0 },
    { "IPv6", 0, 0 },
    { "ICMP", 0, 0 },
    { "IGMP", 0, 0 },
    { "PIM", 0, 0 },
    { "TCP", 0, 0 },
    { "UDP", 0, 0 },
    { "DNS", 0, 0 },
    { "NBNS", 0, 0 },
    { "NBDS", 0, 0 },
    { "HTTP", 0, 0 },
    { "SSDP", 0, 0 },
    { "SNMP", 0, 0 }
};

static void free_protocol_data(struct application_info *info);

size_t read_packet(int sockfd, unsigned char *buffer, size_t len, struct packet **p)
{
    struct mmsghdr msg;
    struct iovec iov;
    unsigned char data[64];
    struct cmsghdr *cmsg;
    struct timeval *val;

    *p = calloc(1, sizeof(struct packet));
    (*p)->ptype = UNKNOWN;
    iov.iov_base = buffer;
    iov.iov_len = len;
    memset(&msg, 0, sizeof(struct mmsghdr));
    msg.msg_hdr.msg_iov = &iov;
    msg.msg_hdr.msg_iovlen = 1;
    msg.msg_hdr.msg_control = data;
    msg.msg_hdr.msg_controllen = 64;

    if (recvmmsg(sockfd, &msg, 1, 0, NULL) == -1) {
        free(*p);
        err_sys("recvmmsg error");
    }
    if (!handle_ethernet(buffer, msg.msg_len, *p)) {
        free_packet(*p);
        return 0;
    }
    for (cmsg = CMSG_FIRSTHDR(&msg.msg_hdr); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg.msg_hdr, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
            val = (struct timeval *) CMSG_DATA(cmsg);
            (*p)->time = *val;
            break;
        }
    }
    (*p)->num = ++pstat[0].num_packets;
    pstat[0].num_bytes += msg.msg_len;
    return msg.msg_len;
}

bool decode_packet(unsigned char *buffer, size_t len, struct packet **p)
{
    *p = calloc(1, sizeof(struct packet));
    (*p)->ptype = UNKNOWN;
    if (!handle_ethernet(buffer, len, *p)) {
        free_packet(*p);
        return false;
    }
    (*p)->num = ++pstat[0].num_packets;
    pstat[0].num_bytes += len;
    return true;
}

void free_packet(void *data)
{
    struct packet *p = (struct packet *) data;

    if (p->eth.ethertype <= ETH_802_3_MAX) {
        free_ethernet802_3_frame(&p->eth);
    } else {
        switch (p->eth.ethertype) {
        case ETH_P_IP:
            if (p->eth.ip) {
                switch (p->eth.ip->protocol) {
                case IPPROTO_UDP:
                    free_protocol_data(&p->eth.ip->udp.data);
                    break;
                case IPPROTO_TCP:
                    free_protocol_data(&p->eth.ip->tcp.data);
                    if (p->eth.ip->tcp.options) {
                        free(p->eth.ip->tcp.options);
                    }
                    break;
                case IPPROTO_PIM:
                    free_pim_packet(&p->eth.ip->pim);
                    break;
                case IPPROTO_ICMP:
                case IPPROTO_IGMP:
                    break;
                default:
                    break;
                }
                free(p->eth.ip);
            }
            break;
        case ETH_P_IPV6:
            if (p->eth.ipv6) {
                switch (p->eth.ipv6->next_header) {
                case IPPROTO_UDP:
                    free_protocol_data(&p->eth.ipv6->udp.data);
                    break;
                case IPPROTO_TCP:
                    free_protocol_data(&p->eth.ipv6->tcp.data);
                    if (p->eth.ipv6->tcp.options) {
                        free(p->eth.ipv6->tcp.options);
                    }
                    break;
                case IPPROTO_PIM:
                    free_pim_packet(&p->eth.ipv6->pim);
                    break;
                case IPPROTO_ICMP:
                case IPPROTO_IGMP:
                    break;
                default:
                    break;
                }
                free(p->eth.ipv6);
            }
            break;
        case ETH_P_ARP:
            if (p->eth.arp) {
                free(p->eth.arp);
            }
            break;
        default:
            break;
        }
    }
    if (p->eth.data) {
        free(p->eth.data);
    }
    free(p);
}

void free_protocol_data(struct application_info *adu)
{
    switch (adu->utype) {
    case DNS:
        free_dns_packet(adu->dns);
        break;
    case NBNS:
        if (adu->nbns) {
            if (adu->nbns->record) {
                free(adu->nbns->record);
            }
            free(adu->nbns);
        }
        break;
    case NBDS:
        free_nbds_packet(adu->nbds);
        break;
    case SSDP:
        if (adu->ssdp) {
            list_free(adu->ssdp, free);
        }
        break;
    case HTTP:
        free_http_packet(adu->http);
        break;
    case SNMP:
    case SNMPTRAP:
        free_snmp_packet(adu->snmp);
        break;
    default:
        break;
    }
}

/*
 * Checks which well-known or registered port the packet originated from or is
 * addressed to. On error the error argument will be set to true, e.g. if
 * checksum correction is enabled and this calculation fails.
 *
 * Returns false if it's an ephemeral port, the port is not yet supported or in
 * case of errors in decoding the packet.
 */
bool check_port(unsigned char *buffer, int n, struct application_info *info,
                uint16_t port, bool *error)
{
    switch (port) {
    case DNS:
    case MDNS:
    case LLMNR:
        return handle_dns(buffer, n, info);
    case NBNS:
        return handle_nbns(buffer, n, info);
    case NBDS:
        return handle_nbds(buffer, n, info);
    case SSDP:
        return handle_ssdp(buffer, n, info);
    /* case HTTP: */
    /*     *error = handle_http(buffer, info, packet_len); */
    /*     return true; */
    case SNMP:
    case SNMPTRAP:
        return handle_snmp(buffer, n, info);
    default:
        return false;
    }
}

unsigned char *get_adu_payload(struct packet *p)
{
    uint8_t protocol;

    protocol = (p->eth.ethertype == ETH_P_IP) ?
        p->eth.ip->protocol : p->eth.ipv6->next_header;
    if (protocol == IPPROTO_TCP) {
        return get_ip_payload(p) + p->eth.ip->tcp.offset * 4;
    }
    if (protocol == IPPROTO_UDP) {
        return get_ip_payload(p) + UDP_HDR_LEN;
    }
    return NULL;
}

void clear_statistics()
{
    for (int i = 0; i <= NUM_PROTOCOLS; i++) {
        pstat[i].num_packets = 0;
        pstat[i].num_bytes = 0;
    }
}

inline uint16_t get_packet_size(struct packet *p)
{
    return p->eth.payload_len + ETH_HLEN;
}
