#include "packet.h"
#include "packet_loop.h"
#include "af.h"
#include "util.h"
#include "debug.h"
#include "string.h"
#include "field.h"

static void print_loop(char *buf, int n, struct packet_data *pdata);
static packet_error handle_loop(struct protocol_info *pinfo, unsigned char *buf,
                                int n, struct packet_data *pdata);

#define LOOP_HDR_LEN 4

static struct protocol_info loop = {
    .short_name = "LOOP",
    .long_name = "Null/Loopback",
    .decode = handle_loop,
    .print_info = print_loop,
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
    struct protocol_info *layer2;
    uint32_t id;
    struct uint_string family;

    if (n < LOOP_HDR_LEN || n > MAX_PACKET_SIZE)
        return DATALINK_ERR;
    field_init(&pdata->data2);
    layer2 = NULL;
    family.val = read_uint32le(&buf);
    family.str = get_bsd_address_family(family.val);
    n -= LOOP_HDR_LEN;
    field_add_value(&pdata->data2, "Address family", FIELD_UINT_STRING, &family);
    pdata->len = LOOP_HDR_LEN;
    pdata->prev = NULL;
    switch (family.val) {
    case AFN_BSD_INET:
        id = get_protocol_id(PKT_LOOP, ETHERTYPE_IP);
        layer2 = get_protocol(id);
        break;
    case AFN_FREEBSD_INET6:
    case AFN_DARWIN_INET6:
        id = get_protocol_id(PKT_LOOP, ETHERTYPE_IPV6);
        layer2 = get_protocol(id);
        break;
    default:
        DEBUG("Unsupported address family %d", family.val);
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


void print_loop(char *buf, int n, struct packet_data *pdata)
{
    struct uint_string *family;

    family = field_search_value(&pdata->data2, "Address family");
    snprintcat(buf, n, "Address family: %s (%d)", family->str, family->val);
}
