#include <stdlib.h>
#include <string.h>
#include "packet_ethernet.h"
#include "packet_stp.h"
#include "packet.h"
#include "packet_llc.h"
#include "../util.h"

#define MIN_CONF_BPDU 35

extern void add_stp_information(void *w, void *sw, void *data);
extern void print_stp(char *buf, int n, void *data);

static char *port_role[] = { "", "Alternate/Backup", "Root", "Designated" };

static struct packet_flags stp_flags[] = {
    { "Topology Change Acknowlegment", 1, NULL },
    { "Agreement", 1, NULL},
    { "Forwarding", 1, NULL },
    { "Learning", 1, NULL },
    { "Port Role:", 2, port_role },
    { "Proposal", 1, NULL },
    { "Topology Change", 1, NULL }
};

static struct protocol_info stp_prot = {
    .short_name = "STP",
    .long_name = "Spanning Tree Protocol",
    .decode = handle_stp,
    .print_pdu = print_stp,
    .add_pdu = add_stp_information
};

void register_stp()
{
    register_protocol(&stp_prot, LAYER802_3, ETH_802_STP);
}

/*
 * IEEE 802.1 Bridge Spanning Tree Protocol
 */
packet_error handle_stp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        void *data)
{
    /* the BPDU shall contain at least 4 bytes */
    if (n < 4) return STP_ERR;

    struct eth_802_llc *llc = data;
    uint16_t protocol_id = buffer[0] << 8 | buffer[1];

    /* protocol id 0x00 identifies the (Rapid) Spanning Tree Protocol */
    if (!protocol_id == 0x0) return STP_ERR;

    pinfo->num_packets++;
    pinfo->num_bytes += n;
    llc->bpdu = mempool_pealloc(sizeof(struct stp_info));
    llc->bpdu->protocol_id = protocol_id;
    llc->bpdu->version = buffer[2];
    llc->bpdu->type = buffer[3];

    /* a configuration BPDU contains at least 35 bytes and RST BPDU 36 bytes */
    if (n >= MIN_CONF_BPDU) {
        llc->bpdu->tcack = (buffer[4] & 0x80) >> 7;
        llc->bpdu->agreement = (buffer[4] & 0x40) >> 6;
        llc->bpdu->forwarding = (buffer[4] & 0x20) >> 5;
        llc->bpdu->learning = (buffer[4] & 0x10) >> 4 ;
        llc->bpdu->port_role = (buffer[4] & 0x0c) >> 2;
        llc->bpdu->proposal = (buffer[4] & 0x02) >> 1;
        llc->bpdu->tc = buffer[4] & 0x01;
        memcpy(llc->bpdu->root_id, &buffer[5], 8);
        llc->bpdu->root_pc = buffer[13] << 24 | buffer[14] << 16 | buffer[15] << 8 | buffer[16];
        memcpy(llc->bpdu->bridge_id, &buffer[17], 8);
        llc->bpdu->port_id = buffer[25] << 8 | buffer[26];
        llc->bpdu->msg_age = buffer[27] << 8 | buffer[28];
        llc->bpdu->max_age = buffer[29] << 8 | buffer[30];
        llc->bpdu->ht = buffer[31] << 8 | buffer[32];
        llc->bpdu->fd = buffer[33] << 8 | buffer[34];
        if (n > MIN_CONF_BPDU) llc->bpdu->version1_len = buffer[35];
    }
    return NO_ERR;
}

char *get_stp_bpdu_type(uint8_t type)
{
    switch (type) {
    case CONFIG:
        return "Configuration BPDU";
    case RST:
        return "Rapid Spanning Tree BPDU";
    case TCN:
        return "Topology Change Notification BPDU";
    default:
        return "";
    }
}

struct packet_flags *get_stp_flags()
{
    return stp_flags;
}

int get_stp_flags_size()
{
    return ARRAY_SIZE(stp_flags);
}
