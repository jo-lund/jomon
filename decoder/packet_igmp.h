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

packet_error handle_igmp(unsigned char *buffer, size_t n, struct igmp_info *info);
char *get_igmp_type(uint8_t type);

#endif
