#ifndef PACKET_IGMP_H
#define PACKET_IGMP_H

#include <stdbool.h>
#include <netinet/in.h>

struct igmp_info {
    uint8_t type;
    uint8_t max_resp_time;
    uint16_t checksum;
    uint32_t group_addr;
};

struct ipv4_info;

bool handle_igmp(unsigned char *buffer, int n, struct igmp_info *info);
char *get_igmp_type(uint8_t type);

#endif
