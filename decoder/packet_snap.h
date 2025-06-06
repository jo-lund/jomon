#ifndef PACKET_SNAP_H
#define PACKET_SNAP_H

#include "packet.h"

/* 802.2 SNAP */
struct snap_info {
    unsigned char oui[3]; /* IEEE Organizationally Unique Identifier */
    uint16_t protocol_id; /* If OUI is 0 the protocol ID is the Ethernet type */
    unsigned char *data;
};

void register_snap(void);

#endif
