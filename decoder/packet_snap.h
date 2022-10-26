#ifndef PACKET_SNAP_H
#define PACKET_SNAP_H

#include "packet.h"

/* 802.2 SNAP */
struct snap_info {
    unsigned char oui[3]; /* IEEE Organizationally Unique Identifier */
    uint16_t protocol_id; /* If OUI is 0 the protocol ID is the Ethernet type */
    unsigned char *data;
};

uint32_t get_snap_oui(struct packet *p);
uint16_t get_snap_id(struct packet *p);
void register_snap(void);
packet_error handle_snap(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata);

#endif
