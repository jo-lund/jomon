#include <string.h>
#include "packet_llc.h"

extern void add_llc_information(void *w, void *sw, void *data);
extern void print_llc(char *buf, int n, void *data);

static packet_error handle_llc(struct protocol_info *pinfo, unsigned char *buffer, int n,
                               struct packet_data *pdata);

static struct protocol_info llc_prot = {
    .short_name = "LLC",
    .long_name = "Logical Link Control",
    .decode = handle_llc,
    .print_pdu = print_llc,
    .add_pdu = add_llc_information
};

void register_llc(void)
{
    register_protocol(&llc_prot, ETH802_3, ETH_802_LLC);
}

packet_error handle_llc(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata)
{
    if (n < LLC_HDR_LEN)
        return DECODE_ERR;

    struct eth_802_llc *llc;
    struct protocol_info *psub;
    uint32_t id;

    pinfo->num_packets++;
    pinfo->num_bytes += n;
    llc = mempool_alloc(sizeof(struct eth_802_llc));
    pdata->data = llc;
    llc->dsap = buffer[0];
    llc->ssap = buffer[1];
    llc->control = buffer[2];
    pdata->len = LLC_HDR_LEN;
    id = get_protocol_id(ETH802_3, (llc->dsap << 8) | llc->ssap);
    if ((llc->dsap << 8 | llc->ssap) == 0xffff) /* invalid id */
        return UNK_PROTOCOL;
    if ((psub = get_protocol(id))) {
        pdata->next = mempool_alloc(sizeof(struct packet_data));
        memset(pdata->next, 0, sizeof(struct packet_data));
        pdata->next->id = id;
        return psub->decode(psub, buffer + LLC_HDR_LEN, n - LLC_HDR_LEN, pdata->next);
    }
    return UNK_PROTOCOL;
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
