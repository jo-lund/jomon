#ifndef PACKET_IGMP_H
#define PACKET_IGMP_H

#include <stdbool.h>
#include <netinet/in.h>
#include "packet.h"

#ifdef __linux__
#define IGMP_v1_HOST_MEMBERSHIP_REPORT IGMP_V1_MEMBERSHIP_REPORT
#define IGMP_v2_HOST_MEMBERSHIP_REPORT IGMP_V2_MEMBERSHIP_REPORT
#endif

struct igmp_info {
    uint8_t type;
    uint8_t max_resp_time;
    uint16_t checksum;
    uint32_t group_addr;
};

void register_igmp();
packet_error handle_igmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata);
char *get_igmp_type(uint8_t type);

#endif
