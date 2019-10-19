#ifndef PACKET_SNAP_H
#define PACKET_SNAP_H

#include "packet.h"

/* 802.2 SNAP */
struct snap_info {
    unsigned char oui[3]; /* IEEE Organizationally Unique Identifier */
    uint16_t protocol_id; /* If OUI is 0 the protocol ID is the Ethernet type */
    unsigned char *data;
};

#define snap_id(p) ((p)->eth.llc->snap->protocol_id)
#define snap_oui(p) ((p)->eth.llc->snap->oui)

uint32_t get_eth802_oui(struct snap_info *snap);
void register_snap();
packet_error handle_snap(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         void *data);

#endif
