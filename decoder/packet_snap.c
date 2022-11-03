#include "packet_snap.h"
#include "packet_llc.h"
#include "../util.h"

#define SNAP_HDR_LEN 5

extern void add_snap_information(void *w, void *sw, void *data);
extern void print_snap(char *buf, int n, void *data);

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
    snap->protocol_id = get_uint16be(buffer);

    /* TODO: handle sub-protocols */
    return NO_ERR;
}

uint32_t get_snap_oui(struct packet *p)
{
    struct packet_data *pdata = get_packet_data(p, ETH_802_SNAP);
    struct snap_info *snap = pdata->data;

    if (snap)
        return snap->oui[0] << 16 | snap->oui[1] << 8 | snap->oui[2];
    return 0;
}

uint16_t get_snap_id(struct packet *p)
{
    struct packet_data *pdata = get_packet_data(p, ETH_802_SNAP);
    struct snap_info *snap = pdata->data;

    if (snap)
        return snap->protocol_id;
    return 0;
}
