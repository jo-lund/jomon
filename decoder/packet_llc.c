#include <string.h>
#include "packet_llc.h"

extern void add_llc_information(void *w, void *sw, void *data);
extern void print_llc(char *buf, int n, void *data);

static struct protocol_info llc_prot = {
    .short_name = "LLC",
    .long_name = "Logical Link Control",
    .decode = handle_llc,
    .print_pdu = print_llc,
    .add_pdu = add_llc_information
};

void register_llc()
{
    register_protocol(&llc_prot, LAYER2, ETH_802_LLC);
}

packet_error handle_llc(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata)
{
    struct eth_802_llc *llc;
    struct protocol_info *psub;

    pinfo->num_packets++;
    pinfo->num_bytes += n;
    llc = mempool_pealloc(sizeof(struct eth_802_llc));
    pdata->data = llc;
    llc->dsap = buffer[0];
    llc->ssap = buffer[1];
    llc->control = buffer[2];
    if ((psub = get_protocol(LAYER3, (llc->dsap << 8) | llc->ssap))) {
        pdata->len = LLC_HDR_LEN;
        pdata->id = (llc->dsap << 8) | llc->ssap;
        pdata->next = mempool_pealloc(sizeof(struct packet_data));
        memset(pdata->next, 0, sizeof(struct packet_data));
        return psub->decode(psub, buffer + LLC_HDR_LEN, n - LLC_HDR_LEN, pdata->next);
    }
    return NO_ERR;

}

enum eth_802_type get_eth802_type(struct packet *p)
{
    struct packet_data *pdata = get_packet_data(p, ETH_802_LLC);
    struct eth_802_llc *llc = pdata->data;

    if (llc) {
        /* DSAP and SSAP specify the upper layer protocols above LLC */
        if (llc->ssap == 0x42 && llc->dsap == 0x42)
            return ETH_802_STP;
        if (llc->ssap == 0xaa && llc->dsap == 0xaa)
            return ETH_802_SNAP;
    }
    return ETH_802_UNKNOWN;
}