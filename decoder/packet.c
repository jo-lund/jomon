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

struct packet_statistics pstat = { 0 };

static void free_protocol_data(struct application_info *info);

size_t read_packet(int sockfd, unsigned char *buffer, size_t len, struct packet **p)
{
    struct mmsghdr msg;
    struct iovec iov;
    unsigned char data[64];
    struct cmsghdr *cmsg;
    struct timeval *val;

    *p = calloc(1, sizeof(struct packet));
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
    if (!handle_ethernet(buffer, msg.msg_len, &(*p)->eth)) {
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
    (*p)->num = ++pstat.num_packets;
    pstat.tot_bytes += msg.msg_len;
    return msg.msg_len;
}

bool decode_packet(unsigned char *buffer, size_t len, struct packet **p)
{
    *p = calloc(1, sizeof(struct packet));
    if (!handle_ethernet(buffer, len, &(*p)->eth)) {
        free_packet(p);
        return false;
    }
    (*p)->num = ++pstat.num_packets;
    pstat.tot_bytes += len;
    return true;
}

void free_packet(void *data)
{
    struct packet *p = (struct packet *) data;

    if (p->eth.ethertype < ETH_P_802_3_MIN) {
        free_ethernet802_3_frame(&p->eth);
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
        break;
    case ETH_P_IPV6:
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
        break;
    case ETH_P_ARP:
        free(p->eth.arp);
        break;
    default:
        break;
    }
    free(p->eth.data);
    free(p);
}

void free_protocol_data(struct application_info *info)
{
    switch (info->utype) {
    case DNS:
        free_dns_packet(info->dns);
        break;
    case NBNS:
        if (info->nbns) {
            if (info->nbns->record) {
                free(info->nbns->record);
            }
            free(info->nbns);
        }
        break;
    case NBDS:
        free_nbds_packet(info->nbds);
        break;
    case SSDP:
        if (info->ssdp) {
            list_free(info->ssdp, free);
        }
        break;
    case HTTP:
        free_http_packet(info->http);
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
    memset(&pstat, 0, sizeof(struct packet_statistics));
}
