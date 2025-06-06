#include "packet_snap.h"
#include "packet_llc.h"
#include "../util.h"

#define SNAP_HDR_LEN 5

extern void add_snap_information(void *w, void *sw, void *data);
extern void print_snap(char *buf, int n, void *data);
static packet_error handle_snap(struct protocol_info *pinfo, unsigned char *buffer,
                                int n, struct packet_data *pdata);

static struct protocol_info snap_prot = {
    .short_name = "SNAP",
    .long_name = "Subnetwork Access Protocol",
    .decode = handle_snap,
    .print_pdu = print_snap,
    .add_pdu = add_snap_information
};

void register_snap(void)
{
    register_protocol(&snap_prot, ETH802_3, ETH_802_SNAP);
}

packet_error handle_snap(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    struct snap_info *snap;
    uint16_t layer;
    uint32_t id;
    struct protocol_info *psub;

    layer = 0;
    snap = mempool_alloc(sizeof(struct snap_info));
    pdata->data = snap;
    pdata->len = n;
    if (n < SNAP_HDR_LEN) {
        memset(snap, 0, sizeof(*snap));
        pdata->error = create_error_string("Packet length (%d) less than SNAP header (%d)", n, SNAP_HDR_LEN);
        return DECODE_ERR;
    }
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    memcpy(snap->oui, buffer, 3);
    buffer += 3;
    snap->protocol_id = read_uint16be(&buffer);
    if (snap->oui[0] == 0 && snap->oui[1] == 0 && snap->oui[2] == 0)
        layer = ETHERNET_II;
    else if (snap->oui[0] == 0 && snap->oui[1] == 0 && snap->oui[2] == 0xc)
        layer = ETH802_3;
    if (layer > 0) {
        id = get_protocol_id(layer, snap->protocol_id);
        if ((psub = get_protocol(id))) {
            pdata->next = mempool_calloc(1, struct packet_data);
            pdata->next->prev = pdata;
            pdata->next->id = id;
            psub->decode(psub, buffer, n - SNAP_HDR_LEN, pdata->next);
        }
    }
    return NO_ERR;
}
