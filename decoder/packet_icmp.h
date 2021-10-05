#ifndef PACKET_ICMP_H
#define PACKET_ICMP_H

#include <stdbool.h>
#include "packet.h"

struct icmp_info {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        struct { /* echo request/reply */
            uint16_t id;
            uint16_t seq_num;
        } echo;
        uint32_t gateway; /* gateway address, used in redirect messages */
    };

    /* id and sequence numbers are used as for echo messages */
    union {
        struct { /* timestamp request/reply */
            /* the timestamps are 32 bits of milliseconds since midnight UT */
            uint32_t originate;
            uint32_t receive;
            uint32_t transmit;
        } timestamp;
        uint32_t addr_mask; /* address mask request/reply */
        uint8_t pointer; /* parameter problem message */
    };
};

void register_icmp();
packet_error handle_icmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata);
char *get_icmp_dest_unreach_code(uint8_t code);
char *get_icmp_redirect_code(uint8_t code);
char *get_icmp_type(uint8_t type);

#endif
