#ifndef PACKET_STP_H
#define PACKET_STP_H

#include <stdbool.h>

enum stp_bpdu_type {
    CONFIG = 0x0,
    RST = 0x2,
    TCN = 0x80
};

/* Spanning Tree Protocol */
struct stp_info {
    uint16_t protocol_id;
    uint8_t version;
    uint8_t type; /* 0x00 Config BPDU, 0x80 TCN BPDU, 0x02 RST BPDU */
    unsigned int tcack : 1; /* topology change acknowledgement */
    unsigned int agreement  : 1;
    unsigned int forwarding : 1;
    unsigned int learning   : 1;
    unsigned int port_role  : 2; /* 01 alternate/backup, 10 root, 11 designated */
    unsigned int proposal   : 1;
    unsigned int tc : 1;  /* topology change */
    uint8_t root_id[8];   /* CIST root id */
    uint32_t root_pc;     /* CIST External Path Cost */
    uint8_t bridge_id[8]; /* CIST Regional Root id */
    uint16_t port_id;
    /* Timer values represent a uint16_t number multiplied by a unit of time of
       1/256 of a second. This permits times in the range [0, 256) seconds. */
    uint16_t msg_age; /* message age */
    uint16_t max_age;
    uint16_t ht; /* hello time */
    uint16_t fd; /* forward delay */
    uint8_t version1_len;
};

struct eth_802_llc;

bool handle_stp(unsigned char *buffer, uint16_t n, struct eth_802_llc *llc);
char *get_stp_bpdu_type(uint8_t type);
struct packet_flags *get_stp_flags();

#endif
