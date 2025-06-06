#ifndef PACKET_LLC_H
#define PACKET_LLC_H

#include "packet.h"

/* Ethernet 802.2 Logical Link Control */
struct eth_802_llc {
    uint8_t dsap; /* destination service access point */
    uint8_t ssap; /* source service access point */
    uint8_t control; /* possible to be 2 bytes? */
};

#define get_llc(p) ((struct eth_802_llc *)(p)->root->next->data)
#define llc_dsap(p) get_llc(p)->dsap
#define llc_ssap(p) get_llc(p)->ssap
#define llc_control(p) get_llc(p)->control

void register_llc(void);

#endif
