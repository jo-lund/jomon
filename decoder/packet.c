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

allocator_t d_alloc = {
    .alloc = mempool_pealloc,
    .dealloc = NULL
};

uint32_t total_packets;
uint64_t total_bytes;
static hashmap_t *info;
static hashmap_t *protocols;

void decoder_init()
{
    info = hashmap_init(64, hash_string, compare_string);
    protocols = hashmap_init(64, hash_uint16, compare_uint);
    for (unsigned int i = 0; i < ARRAY_SIZE(decoder_functions); i++) {
        decoder_functions[i]();
    }
}

void decoder_exit()
{
    hashmap_free(protocols);
    hashmap_free(info);
}

void register_protocol(struct protocol_info *pinfo, uint16_t layer, uint16_t id)
{
    if (pinfo) {
        hashmap_insert(protocols, UINT_TO_PTR(get_protocol_id(layer, id)), pinfo);
        hashmap_insert(info, pinfo->short_name, pinfo);
    }
}

struct protocol_info *get_protocol(uint32_t id)
{
    return hashmap_get(protocols, UINT_TO_PTR(id));
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
    (*p)->buf = mempool_pecopy(buffer, len); /* store the original frame in buf */
    (*p)->len = len;
    if (!handle_ethernet(buffer, len, *p)) {
        free_packets(*p);
        return false;
    }
    (*p)->ptype = ETHERNET;
    (*p)->num = ++total_packets;
    total_bytes += len;
    return true;
}

void free_packets(void *data)
{
    mempool_pefree(data);
}

packet_error call_data_decoder(struct packet_data *pdata, uint8_t transport,
                               unsigned char *buf, int n)
{
    struct protocol_info *pinfo;
    packet_error err = UNK_PROTOCOL;

    if (!pdata)
        return DECODE_ERR;

    if ((pinfo = get_protocol(pdata->id))) {
        pdata->next = mempool_pealloc(sizeof(struct packet_data));
        memset(pdata->next, 0, sizeof(struct packet_data));
        pdata->next->transport = transport;
        pdata->next->id = pdata->id;
        if ((err = pinfo->decode(pinfo, buf, n, pdata->next)) != NO_ERR) {
            mempool_pefree(pdata->next);
            pdata->next = NULL;
        }
    } else {
        pdata->next = NULL;
    }
    return err;
}

// TODO: Improve this
unsigned char *get_adu_payload(struct packet *p)
{
    struct packet_data *pdata = p->root;
    int i = 0;

    while (pdata) {
        i += pdata->len;
        if (get_protocol_layer(pdata->id) == PORT)
            return p->buf + i;
        pdata = pdata->next;
    }
    return NULL;
}

// TODO: Improve this
unsigned int get_adu_payload_len(struct packet *p)
{
    struct packet_data *pdata = p->root;
    unsigned int len = p->len;

    while (pdata) {
        len -= pdata->len;
        if (get_protocol_layer(pdata->id) == PORT)
            return len;
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
    return get_packet_data(p, get_protocol_id(IP_PROTOCOL, IPPROTO_TCP)) != NULL;
}

struct packet_data *get_packet_data(const struct packet *p, uint32_t id)
{
    struct packet_data *pdata = p->root;

    while (pdata) {
        if (pdata->id == id && pdata->next)
            return pdata->next;
        pdata = pdata->next;
    }
    return NULL;
}
