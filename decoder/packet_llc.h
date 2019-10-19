#ifndef PACKET_LLC_H
#define PACKET_LLC_H

#include "packet.h"

/* Ethernet 802.2 Logical Link Control */
struct eth_802_llc {
    uint8_t dsap; /* destination service access point */
    uint8_t ssap; /* source service access point */
    uint8_t control; /* possible to be 2 bytes? */
    union {
        struct snap_info *snap;
        struct stp_info *bpdu;
    };
};

#define llc_dsap(p) ((p)->eth.llc->dsap)
#define llc_ssap(p) ((p)->eth.llc->ssap)
#define llc_control(p) ((p)->eth.llc->control)
#define get_snap(p) ((p)->eth.llc->snap)
#define get_stp(p) ((p)->eth.llc->bpdu)

enum eth_802_type get_eth802_type(struct eth_802_llc *llc);
void register_llc();
packet_error handle_llc(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        void *data);

#endif
