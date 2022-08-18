#ifndef PACKET_ICMP_H
#define PACKET_ICMP_H

#include <stdbool.h>
#include "packet.h"

struct icmp_info {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    union {
        struct {
            uint16_t id;
            uint16_t seq_num;
        };
        uint32_t gateway; /* gateway address, used in redirect messages */
        uint8_t pointer; /* parameter problem message */
    };
    union {
        struct { /* echo request/reply */
            unsigned char *data;
            uint16_t len;
        } echo;
        struct { /* timestamp request/reply */
            /* the timestamps are 32 bits of milliseconds since midnight UT */
            uint32_t originate;
            uint32_t receive;
            uint32_t transmit;
        } timestamp;
        uint32_t addr_mask; /* address mask request/reply */
    };
};

void register_icmp(void);
char *get_icmp_dest_unreach_code(uint8_t code);
char *get_icmp_redirect_code(uint8_t code);
char *get_icmp_type(uint8_t type);

#endif
