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

allocator_t d_alloc = {
    .alloc = mempool_pealloc,
    .dealloc = NULL
};

static bool filter_protocol(struct protocol_info *pinfo);

static hashmap_t *layer2;
static hashmap_t *layer3;
static hashmap_t *layer4;
static hashmap_t *l802_3;
static hashmap_t *protocols;
uint32_t total_packets;
uint64_t total_bytes;

static unsigned int prot_hash(const void *key)
{
   unsigned int hash = 5381;
   char *val = (char *) key;

   while (*val != '\0') {
       hash = ((hash << 5) + hash) + *val++;
   }
   return hash;
}

static inline int prot_compare(const void *e1, const void *e2)
{
    return strcmp((char *) e1, (char *) e2);
}

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
    protocols = hashmap_init(8, prot_hash, prot_compare);
    l802_3 = hashmap_init(16, hash, compare);
    layer2 = hashmap_init(16, hash, compare);
    layer3 = hashmap_init(16, hash, compare);
    layer4 = hashmap_init(32, hash, compare);
    hashmap_insert(protocols, LAYER802_3, l802_3);
    hashmap_insert(protocols, LAYER2, layer2);
    hashmap_insert(protocols, LAYER3, layer3);
    hashmap_insert(protocols, LAYER4, layer4);
    for (unsigned int i = 0; i < ARRAY_SIZE(decoder_functions); i++) {
        decoder_functions[i]();
    }
}

void decoder_exit()
{
    const hashmap_iterator *it = hashmap_first(protocols);

    while (it) {
        hashmap_free(it->data);
        it = hashmap_next(protocols, it);
    }
    hashmap_free(protocols);
}

void register_protocol(struct protocol_info *pinfo, char *layer)
{
    if (pinfo) {
        hashmap_t *l = hashmap_get(protocols, layer);

        hashmap_insert(l, (void *) (uintptr_t) pinfo->port, pinfo);
    }
}

struct protocol_info *get_protocol(char *layer, uint16_t id)
{
    hashmap_t *l = hashmap_get(protocols, layer);

    return hashmap_get(l, (void *) (uintptr_t) id);
}

void traverse_protocols(protocol_handler fn, void *arg)
{
    const hashmap_iterator *pit = hashmap_first(protocols);

    while (pit) {
        const hashmap_iterator *lit;
        struct protocol_info *pinfo;
        hashmap_t *layer;

        layer = pit->data;
        lit = hashmap_first(layer);
        while (lit) {
            pinfo = lit->data;
            if (filter_protocol(pinfo))
                fn(pinfo, arg);
            lit = hashmap_next(layer, lit);
        }
        pit = hashmap_next(protocols, pit);
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
    (*p)->num = ++total_packets;
    total_bytes += len;
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
    struct protocol_info *pinfo = hashmap_get(layer4, (void *) (uintptr_t) port);

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

static void clear_packet(struct protocol_info *pinfo, void *user UNUSED)
{
    pinfo->num_bytes = 0;
    pinfo->num_packets = 0;
}

void clear_statistics()
{
    total_bytes = 0;
    total_packets = 0;
    traverse_protocols(clear_packet, NULL);
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
