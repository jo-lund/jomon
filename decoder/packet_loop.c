#include <stdio.h>
#include "packet.h"
#include "packet_loop.h"
#include "af.h"
#include "util.h"
#include "debug.h"
#include "string.h"

extern void add_loop_information(void *w, void *sw, void *data);
extern void print_loop(char *buf, int n, void *data);
static packet_error handle_loop(struct protocol_info *pinfo, unsigned char *buf,
                                int n, struct packet_data *pdata);

#define LOOP_HDR_LEN 4

static struct protocol_info loop = {
    .short_name = "LOOP",
    .long_name = "Null/Loopback",
    .decode = handle_loop,
    .print_pdu = print_loop,
    .add_pdu = add_loop_information
};

void register_loop(void)
{
    register_protocol(&loop, DATALINK, LINKTYPE_NULL);
}

/*
 * The LINKTYPE_NULL header is 4 bytes long. It contains a 32-bit integer that
 * specifies the address family.
 */
packet_error handle_loop(struct protocol_info *pinfo UNUSED, unsigned char *buf,
                             int n, struct packet_data *pdata)
{
    uint32_t family;
    struct protocol_info *layer2;
    uint32_t id;

    if (n < LOOP_HDR_LEN || n > MAX_PACKET_SIZE)
        return DATALINK_ERR;
    layer2 = NULL;
    family = read_uint32le(&buf);
    n -= LOOP_HDR_LEN;
    pdata->data = mempool_alloc(sizeof(uint32_t));
    *(uint32_t *)pdata->data = family;
    pdata->len = LOOP_HDR_LEN;
    pdata->prev = NULL;
    switch (family) {
    case AF_BSD_INET:
        id = get_protocol_id(PKT_LOOP, ETHERTYPE_IP);
        layer2 = get_protocol(id);
        break;
    case AF_FREEBSD_INET6:
    case AF_DARWIN_INET6:
        id = get_protocol_id(PKT_LOOP, ETHERTYPE_IPV6);
        layer2 = get_protocol(id);
        break;
    default:
        DEBUG("Unsupported address family %d", family);
        return UNK_PROTOCOL;
    }
    if (layer2) {
        pdata->next = mempool_calloc(1, struct packet_data);
        pdata->next->prev = pdata;
        pdata->next->id = id;
        layer2->decode(layer2, buf, n, pdata->next);
        return NO_ERR;
    }
    return UNK_PROTOCOL;
}

void loop2string(char *buf, int n, void *data)
{
    uint32_t family;

    family = *(uint32_t *) data;
    snprintcat(buf, n, "Address family: %s (%d)",
               get_bsd_address_family(family), family);
}
