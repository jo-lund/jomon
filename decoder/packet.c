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
#include "tcp_analyzer.h"
#include "host_analyzer.h"
#include "dns_cache.h"
#include "register.h"
#include "../hash.h"

allocator_t d_alloc = {
    .alloc = mempool_alloc,
    .dealloc = NULL
};

uint32_t total_packets;
uint64_t total_bytes;
static hashmap_t *info;
static hashmap_t *protocols;

void decoder_init(void)
{
    info = hashmap_init(64, hashdjb_string, compare_string);
    protocols = hashmap_init(64, hashdjb_uint16, compare_uint);
    for (unsigned int i = 0; i < ARRAY_SIZE(decoder_functions); i++) {
        decoder_functions[i]();
    }
}

void decoder_exit(void)
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
    const hashmap_iterator *it;
    struct protocol_info *pinfo;

    HASHMAP_FOREACH(info, it) {
        pinfo = it->data;
        fn(pinfo, arg);
    }
}

bool decode_packet(unsigned char *buffer, size_t len, struct packet **p)
{
    *p = mempool_alloc(sizeof(struct packet));
    (*p)->buf = mempool_copy(buffer, len); /* store the original frame in buf */
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
    mempool_free(data);
}

packet_error call_data_decoder(struct packet_data *pdata, uint8_t transport,
                               unsigned char *buf, int n)
{
    struct protocol_info *pinfo;
    packet_error err = UNK_PROTOCOL;

    if (!pdata)
        return DECODE_ERR;

    if ((pinfo = get_protocol(pdata->id))) {
        pdata->next = mempool_alloc(sizeof(struct packet_data));
        memset(pdata->next, 0, sizeof(struct packet_data));
        pdata->next->transport = transport;
        pdata->next->id = pdata->id;
        pdata->next->prev = pdata;
        if ((err = pinfo->decode(pinfo, buf, n, pdata->next)) != NO_ERR) {
            mempool_free(pdata->next);
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

void clear_statistics(void)
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
