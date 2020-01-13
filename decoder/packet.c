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

#define NUM_LAYERS 3

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
    for (int i = 0; i < NUM_LAYERS; i++) {
        protocols[i] = hashmap_init(16, hash_uint16, compare_uint);
    }
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

void register_protocol(struct protocol_info *pinfo, unsigned int layer, uint16_t id)
{
    if (pinfo && layer < NUM_LAYERS) {
        hashmap_t *l = protocols[layer];

        hashmap_insert(l, (void *) (uintptr_t) id, pinfo);
        hashmap_insert(info, pinfo->short_name, pinfo);
    }
}

struct protocol_info *get_protocol(int layer, uint16_t id)
{
    if (layer < NUM_LAYERS) {
        hashmap_t *l = protocols[layer];

        return hashmap_get(l, (void *) (uintptr_t) id);
    }
    return NULL;
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

    /* store the original frame in buf */
    (*p)->buf = mempool_pecopy(buffer, len);
    (*p)->len = len;

    if (!handle_ethernet(buffer, len, *p)) {
        free_packets(*p);
        return false;
    }
    (*p)->ptype = ETHERNET;
    (*p)->num = ++total_packets;
    total_bytes += len;
    if ((*p)->perr == NO_ERR && is_tcp(*p)) {
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
packet_error check_port(unsigned char *buffer, int n, struct packet_data *p,
                        uint16_t port)
{
    struct protocol_info *pinfo = hashmap_get(protocols[LAYER4], (void *) (uintptr_t) port);

    if (pinfo)
        return pinfo->decode(pinfo, buffer, n, p);
    return UNK_PROTOCOL;
}

unsigned char *get_adu_payload(struct packet *p)
{
    struct packet_data *pdata = p->root;
    int i = 0;
    int layer = 0;

    while (pdata) {
        i += pdata->len;
        if (layer == LAYER4)
            return p->buf + i;
        layer++;
        pdata = pdata->next;
    }
    return NULL;
}

unsigned int get_adu_payload_len(struct packet *p)
{
    struct packet_data *pdata = p->root;
    unsigned int len = p->len;
    int layer = 0;

    while (pdata) {
        len -= pdata->len;
        if (layer == LAYER4)
            return len;
        layer++;
        pdata = pdata->next;
    }
    return 0;
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

bool is_tcp(struct packet *p)
{
    struct packet_data *pdata = p->root;

    while (pdata) {
        if (pdata->id == IPPROTO_TCP)
            return true;
        pdata = pdata->next;
    }
    return false;
}

struct packet_data *get_packet_data(const struct packet *p, uint16_t id)
{
    struct packet_data *pdata = p->root;

    while (pdata) {
        if (pdata->id == id && pdata->next)
            return pdata->next;
        pdata = pdata->next;
    }
    return NULL;
}
