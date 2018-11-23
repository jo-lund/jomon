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
#include "packet_imap.h"
#include "tcp_analyzer.h"
#include "host_analyzer.h"
#include "dns_cache.h"

/* This needs to be in the same order as enum protocols, see packet.h */
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
    { "SNMP", 0, 0 },
    { "IMAP", 0, 0 }
};

allocator_t d_alloc = {
    .alloc = mempool_pealloc,
    .dealloc = NULL
};

size_t read_packet(int sockfd, unsigned char *buffer, size_t len, struct packet **p)
{
    struct mmsghdr msg;
    struct iovec iov;
    unsigned char data[64];
    struct cmsghdr *cmsg;
    struct timeval *val;

    *p = mempool_pealloc(sizeof(struct packet));
    (*p)->ptype = UNKNOWN;
    iov.iov_base = buffer;
    iov.iov_len = len;
    memset(&msg, 0, sizeof(struct mmsghdr));
    msg.msg_hdr.msg_iov = &iov;
    msg.msg_hdr.msg_iovlen = 1;
    msg.msg_hdr.msg_control = data;
    msg.msg_hdr.msg_controllen = 64;

    if (recvmmsg(sockfd, &msg, 1, 0, NULL) == -1) {
        free_packets(*p);
        err_sys("recvmmsg error");
    }
    if (!handle_ethernet(buffer, msg.msg_len, *p)) {
        free_packets(*p);
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
    host_analyzer_investigate(*p);
    return msg.msg_len;
}

bool decode_packet(unsigned char *buffer, size_t len, struct packet **p)
{
    *p = mempool_pealloc(sizeof(struct packet));
    (*p)->ptype = UNKNOWN;
    if (!handle_ethernet(buffer, len, *p)) {
        free_packets(*p);
        return false;
    }
    (*p)->num = ++pstat[0].num_packets;
    pstat[0].num_bytes += len;
    host_analyzer_investigate(*p);
    return true;
}

void free_packets(void *data)
{
    mempool_pefree(data);
}

/*
 * Checks which well-known or registered port the packet originated from or is
 * addressed to.
 *
 * Returns the error status. This is set to "unknown protocol" if it's an
 * ephemeral port or the port is not yet supported.
 */
packet_error check_port(unsigned char *buffer, int n, struct application_info *adu,
                        uint16_t port, bool is_tcp)
{
    switch (port) {
    case DNS:
    case MDNS:
    case LLMNR:
        return handle_dns(buffer, n, adu, is_tcp);
    case HTTP:
        return handle_http(buffer, n, adu);
    case NBNS:
        return handle_nbns(buffer, n, adu);
    case NBDS:
        return handle_nbds(buffer, n, adu);
    case SSDP:
        return handle_ssdp(buffer, n, adu);
    case SNMP:
    case SNMPTRAP:
        return handle_snmp(buffer, n, adu);
    case IMAP:
        return handle_imap(buffer, n, adu);
    default:
        return UNK_PROTOCOL;
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
    tcp_analyzer_clear();
    host_analyzer_clear();
    dns_cache_clear();
}

uint16_t get_packet_size(struct packet *p)
{
    return p->eth.payload_len + ETH_HLEN;
}
