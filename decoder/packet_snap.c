#include <stdio.h>
#include "packet_snap.h"
#include "packet.h"
#include "util.h"
#include "field.h"

#define SNAP_HDR_LEN 5

static void print_snap(char *buf, int n, struct packet_data *data);
static packet_error handle_snap(struct protocol_info *pinfo, unsigned char *buffer,
                                int n, struct packet_data *pdata);

static struct protocol_info snap = {
    .short_name = "SNAP",
    .long_name = "Subnetwork Access Protocol",
    .decode = handle_snap,
    .print_info = print_snap,
};

void register_snap(void)
{
    register_protocol(&snap, ETH802_3, ETH_802_SNAP);
}

packet_error handle_snap(struct protocol_info *pinfo, unsigned char *buf, int n, struct packet_data *pdata)
{
    uint16_t layer;
    uint32_t id;
    struct protocol_info *psub;
    unsigned char oui[3];
    uint16_t protocol_id;

    if (n < SNAP_HDR_LEN) {
        pdata->error = create_error_string("Packet length (%d) less than SNAP header (%d)", n, SNAP_HDR_LEN);
        return DECODE_ERR;
    }
    layer = 0;
    field_init(&pdata->data);
    oui[0] = buf[0];
    oui[1] = buf[1];
    oui[2] = buf[2];
    buf += 3;
    field_add_bytes(&pdata->data, "IEEE Organizationally Unique Identifier (OUI)", FIELD_UINT24, oui, 3);
    protocol_id = read_uint16be(&buf);
    field_add_value(&pdata->data, "Protocol Id", FIELD_UINT16, UINT_TO_PTR(protocol_id));
    pdata->len = SNAP_HDR_LEN;
    pinfo->num_packets++;
    pinfo->num_bytes += SNAP_HDR_LEN;
    if (oui[0] == 0 && oui[1] == 0 && oui[2] == 0)
        layer = ETHERNET_II;
    else if (oui[0] == 0 && oui[1] == 0 && oui[2] == 0xc)
        layer = ETH802_3;
    if (layer > 0) {
        id = get_protocol_id(layer, protocol_id);
        if ((psub = get_protocol(id))) {
            pdata->next = mempool_calloc(1, struct packet_data);
            pdata->next->id = id;
            psub->decode(psub, buf, n - SNAP_HDR_LEN, pdata->next);
        }
    }
    return NO_ERR;
}

void print_snap(char *buf, int n, struct packet_data *pdata)
{
    unsigned char *oui;
    uint16_t id;
    const struct field *f = NULL;

    f = field_get_next(&pdata->data, f);
    oui = field_get_value(f);
    f = field_get_next(&pdata->data, f);
    id = field_get_uint16(f);
    snprintf(buf, n, "OUI: 0x%06x  Protocol Id: 0x%04x",
             oui[0] << 16 | oui[1] << 8 | oui[2], id);
}
