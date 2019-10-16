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
#include "../util.h"
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
#include "packet_tls.h"
#include "tcp_analyzer.h"
#include "host_analyzer.h"
#include "dns_cache.h"
#include "register.h"

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
};

allocator_t d_alloc = {
    .alloc = mempool_pealloc,
    .dealloc = NULL
};

static hashmap_t *protocols;

static bool filter_protocol(struct protocol_info *pinfo);

static unsigned int hash(const void *key)
{
   unsigned int hash = 5381;
   uintptr_t val = (uintptr_t) key;

   for (unsigned int i = 0; i < 2; i++) {
       hash = ((hash << 5) + hash) + ((val >> (i * 8)) & 0xff);
   }
   return hash;
}

static inline int compare(const void *e1, const void *e2)
{
    return (uintptr_t) e1 - (uintptr_t) e2;
}

void decoder_init()
{
    protocols = hashmap_init(24, hash, compare);
    for (unsigned int i = 0; i < ARRAY_SIZE(decoder_functions); i++) {
        decoder_functions[i]();
    }
}

void decoder_exit()
{
    hashmap_free(protocols);
}

void register_protocol(struct protocol_info *pinfo, uint16_t port)
{
    if (pinfo)
        hashmap_insert(protocols, (void *) (uintptr_t) port, pinfo);
}

struct protocol_info *get_protocol(uint16_t port)
{
    return hashmap_get(protocols, (void *) (uintptr_t) port);
}

void traverse_protocols(protocol_handler fn, void *arg)
{
    const hashmap_iterator *it = hashmap_first(protocols);
    struct protocol_info *pinfo;

    while (it) {
        pinfo = it->data;
        if (filter_protocol(pinfo))
            fn(pinfo, arg);
        it = hashmap_next(protocols, it);
    }
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
    if (is_tcp(*p)) {
        tcp_analyzer_check_stream(*p);
    }
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
                        uint16_t port)
{
    struct protocol_info *pinfo = hashmap_get(protocols, (void *) (uintptr_t) port);

    if (pinfo)
        return pinfo->decode(pinfo, buffer, n, adu);
    return UNK_PROTOCOL;
}

unsigned char *get_adu_payload(struct packet *p)
{
    if (ethertype(p) == ETH_P_IP) {
        if (ipv4_protocol(p) == IPPROTO_TCP)
            return get_ip_payload(p) + p->eth.ipv4->tcp->offset * 4;
        if (ipv4_protocol(p) == IPPROTO_UDP)
            return get_ip_payload(p) + UDP_HDR_LEN;
    } else {
        if (ipv6_protocol(p) == IPPROTO_TCP)
            return get_ip_payload(p) + p->eth.ipv6->tcp->offset * 4;
        if (ipv6_protocol(p) == IPPROTO_UDP)
            return get_ip_payload(p) + UDP_HDR_LEN;
    }
    return NULL;
}

struct application_info *get_adu_info(struct packet *p)
{
    if (ethertype(p) == ETH_P_IP) {
        if (ipv4_protocol(p) == IPPROTO_TCP)
            return &tcp_data(p, v4);
        if (ipv4_protocol(p) == IPPROTO_UDP)
            return &udp_data(p, v4);
    } else {
        if (ipv6_protocol(p) == IPPROTO_TCP)
            return &tcp_data(p, v6);
        if (ipv6_protocol(p) == IPPROTO_UDP)
            return &udp_data(p, v6);
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

bool is_tcp(struct packet *p)
{
    uint8_t protocol = 0;

    if (p->eth.ethertype == ETH_P_IP) {
        protocol = p->eth.ipv4->protocol;
    } else if (p->eth.ethertype == ETH_P_IPV6) {
        protocol = p->eth.ipv6->next_header;
    }
    return protocol == IPPROTO_TCP;
}

// TODO: Fix this
bool filter_protocol(struct protocol_info *pinfo)
{
    static const enum port filter[] = { SNMPTRAP, IMAPS };

    for (unsigned int i = 0; i < ARRAY_SIZE(filter); i++) {
        if (pinfo->port == filter[i])
            return false;
    }
    return true;
}
