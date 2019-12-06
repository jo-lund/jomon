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
#include "../hash.h"

#define NUM_LAYERS 4

allocator_t d_alloc = {
    .alloc = mempool_pealloc,
    .dealloc = NULL
};

uint32_t total_packets;
uint64_t total_bytes;
static hashmap_t *info;
static hashmap_t *protocols[NUM_LAYERS];

void decoder_init()
{
    info = hashmap_init(64, hash_string, compare_string);
    protocols[LAYER802_3] = hashmap_init(16, hash_uint16, compare_uint);
    protocols[LAYER2] = hashmap_init(16, hash_uint16, compare_uint);
    protocols[LAYER3] = hashmap_init(16, hash_uint16, compare_uint);
    protocols[LAYER4] = hashmap_init(32, hash_uint16, compare_uint);
    for (unsigned int i = 0; i < ARRAY_SIZE(decoder_functions); i++) {
        decoder_functions[i]();
    }
}

void decoder_exit()
{
    for (int i = 0; i < NUM_LAYERS; i++) {
        hashmap_free(protocols[i]);
    }
    hashmap_free(info);
}

void register_protocol(struct protocol_info *pinfo, int layer, uint16_t id)
{
    if (pinfo) {
        hashmap_t *l = protocols[layer];

        hashmap_insert(l, (void *) (uintptr_t) id, pinfo);
        hashmap_insert(info, pinfo->short_name, pinfo);
    }
}

struct protocol_info *get_protocol(int layer, uint16_t id)
{
    hashmap_t *l = protocols[layer];

    return hashmap_get(l, (void *) (uintptr_t) id);
}

void traverse_protocols(protocol_handler fn, void *arg)
{
    const hashmap_iterator *it = hashmap_first(info);
    struct protocol_info *pinfo;

    while (it) {
        pinfo = it->data;
        fn(pinfo, arg);
        it = hashmap_next(info, it);
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
    struct protocol_info *pinfo = hashmap_get(protocols[LAYER4], (void *) (uintptr_t) port);

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
