#include "packet_snap.h"
#include "packet_llc.h"
#include "../util.h"

extern void add_snap_information(void *w, void *sw, void *data);
extern void print_snap(char *buf, int n, void *data);

static struct protocol_info snap_prot = {
    .short_name = "SNAP",
    .long_name = "Subnetwork Access Protocol",
    .decode = handle_snap,
    .print_pdu = print_snap,
    .add_pdu = add_snap_information
};

void register_snap()
{
    register_protocol(&snap_prot, LAYER802_3, ETH_802_SNAP);
}

packet_error handle_snap(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         void *data)
{
    struct eth_802_llc *llc = data;

    pinfo->num_packets++;
    pinfo->num_bytes += n;
    llc->snap = mempool_pealloc(sizeof(struct snap_info));
    memcpy(llc->snap->oui, buffer, 3);
    buffer += 3; /* skip first 3 bytes of 802.2 SNAP */
    llc->snap->protocol_id = get_uint16be(buffer);

    /* TODO: handle sub-protocols */
    return NO_ERR;
}

uint32_t get_eth802_oui(struct snap_info *snap)
{
    return snap->oui[0] << 16 | snap->oui[1] << 8 | snap->oui[2];
}
