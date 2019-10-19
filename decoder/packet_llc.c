#include "packet_llc.h"

extern void add_llc_information(void *w, void *sw, void *data);
extern void print_llc(char *buf, int n, void *data);

static struct protocol_info llc_prot = {
    .short_name = "LLC",
    .long_name = "Logical Link Control",
    .port = ETH_802_LLC,
    .decode = handle_llc,
    .print_pdu = print_llc,
    .add_pdu = add_llc_information
};

void register_llc()
{
    register_protocol(&llc_prot, LAYER802_3);
}

packet_error handle_llc(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         void *data)
{
    struct eth_info *eth = data;
    struct protocol_info *psub;

    pinfo->num_packets++;
    pinfo->num_bytes += n;
    eth->llc = mempool_pealloc(sizeof(struct eth_802_llc));
    eth->llc->dsap = buffer[0];
    eth->llc->ssap = buffer[1];
    eth->llc->control = buffer[2];
    if ((psub = get_protocol(LAYER802_3, (eth->llc->dsap << 8) | eth->llc->ssap)))
        return psub->decode(psub, buffer + LLC_HDR_LEN, n - LLC_HDR_LEN, eth->llc);
    return NO_ERR;
}

enum eth_802_type get_eth802_type(struct eth_802_llc *llc)
{
    /* DSAP and SSAP specify the upper layer protocols above LLC */
    if (llc->ssap == 0x42 && llc->dsap == 0x42) return ETH_802_STP;
    if (llc->ssap == 0xaa && llc->dsap == 0xaa) return ETH_802_SNAP;

    return ETH_802_UNKNOWN;
}
