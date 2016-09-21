#ifndef PACKET_IGMP_H
#define PACKET_IGMP_H

#include <stdbool.h>

struct igmp_info {
    uint8_t type;
    uint8_t max_resp_time;
    uint16_t checksum;
    char group_addr[INET_ADDRSTRLEN];
};

struct ip_info;

bool handle_igmp(unsigned char *buffer, int n, struct ip_info *info);
char *get_igmp_type(uint8_t type);

#endif
