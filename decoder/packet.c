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
#include "../monitor.h"
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

void register_protocol(struct protocol_info *pinfo, uint16_t layer, uint16_t key)
{
    if (pinfo) {
        hashmap_insert(protocols, UINT_TO_PTR(get_protocol_id(layer, key)), pinfo);
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

bool decode_packet(iface_handle_t *h, unsigned char *buffer, size_t len, struct packet **p)
{
    struct protocol_info *pinfo;

    *p = mempool_alloc(sizeof(struct packet));
    (*p)->buf = mempool_copy(buffer, len); /* store the original frame in buf */
    (*p)->len = len;
    (*p)->root = mempool_calloc(struct packet_data);
    (*p)->root->id = get_protocol_id(DATALINK, h->linktype);
    if ((pinfo = get_protocol((*p)->root->id)) == NULL)
        return false;
    if (((*p)->perr = pinfo->decode(pinfo, (*p)->buf, len, (*p)->root)) == DATALINK_ERR) {
        free_packets(*p);
        return false;
    }
    (*p)->num = ++total_packets;
    total_bytes += len;
    return true;
}

void free_packets(void *data)
{
    mempool_free(data);
}

packet_error call_data_decoder(uint32_t id, struct packet_data *p, uint8_t transport,
                               unsigned char *buf, int n)
{
    struct protocol_info *pinfo;
    packet_error err = UNK_PROTOCOL;
    struct packet_data *pdata;

    if ((pinfo = get_protocol(id))) {
        pdata = mempool_alloc(sizeof(struct packet_data));
        memset(pdata, 0, sizeof(struct packet_data));
        pdata->transport = transport;
        pdata->id = id;
        pdata->prev = p;
        p->next = pdata;
        if ((err = pinfo->decode(pinfo, buf, n, pdata)) != NO_ERR) {
            mempool_free(pdata);
            p->next = NULL;
        }
    }
    return err;
}

unsigned char *get_adu_payload(struct packet *p)
{
    struct packet_data *pdata = p->root;
    int i = 0;

    while (pdata) {
        if (get_protocol_key(pdata->id) == IPPROTO_TCP ||
            get_protocol_key(pdata->id) == IPPROTO_UDP)
            return p->buf + i + pdata->len;
        i += pdata->len;
        pdata = pdata->next;
    }
    return NULL;
}

unsigned int get_adu_payload_len(struct packet *p)
{
    struct packet_data *pdata = p->root;
    unsigned int len = p->len;

    while (pdata) {
        if (get_protocol_key(pdata->id) == IPPROTO_TCP ||
            get_protocol_key(pdata->id) == IPPROTO_UDP)
            return len - pdata->len;
        len -= pdata->len;
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
        if (pdata->id == id)
            return pdata;
        pdata = pdata->next;
    }
    return NULL;
}
