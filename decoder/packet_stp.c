#include <stdlib.h>
#include <string.h>
#include "packet.h"

/*
 * IEEE 802.1 Bridge Spanning Tree Protocol
 */
bool handle_stp(unsigned char *buffer, uint16_t n, struct eth_802_llc *llc)
{
    /* the BPDU shall contain at least 4 bytes */
    if (n < 4) return false;

    uint16_t protocol_id = buffer[0] << 8 | buffer[1];

    /* protocol id 0x00 identifies the (Rapid) Spanning Tree Protocol */
    if (!protocol_id == 0x0) return false;

    llc->bpdu = malloc(sizeof(struct stp_info));
    llc->bpdu->protocol_id = protocol_id;
    llc->bpdu->version = buffer[2];
    llc->bpdu->type = buffer[3];

    /* a configuration BPDU contains at least 35 bytes and RST BPDU 36 bytes */
    if (n >= 35) {
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
        if (n > 35) llc->bpdu->version1_len = buffer[35];
    }
    return true;
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