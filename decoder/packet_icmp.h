#ifndef PACKET_ICMP_H
#define PACKET_ICMP_H

#include <stdbool.h>

struct icmp_info {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        struct { /* used in echo request/reply messages */
            uint16_t id;
            uint16_t seq_num;
        } echo;
        uint32_t gateway; /* gateway address, used in redirect messages */
    };
};

struct ipv4_info;

bool handle_icmp(unsigned char *buffer, int n, struct icmp_info *info);
char *get_icmp_dest_unreach_code(uint8_t code);
char *get_icmp_type(uint8_t type);

#endif
