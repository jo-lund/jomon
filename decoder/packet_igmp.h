#ifndef PACKET_IGMP_H
#define PACKET_IGMP_H

#include <stdbool.h>
#include <netinet/in.h>
#include "packet.h"

#ifdef __linux__
#define IGMP_v1_HOST_MEMBERSHIP_REPORT IGMP_V1_MEMBERSHIP_REPORT
#define IGMP_v2_HOST_MEMBERSHIP_REPORT IGMP_V2_MEMBERSHIP_REPORT
#endif
#define IGMP_v3_HOST_MEMBERSHIP_REPORT 0x22

enum igmp3_group_record_type {
    MODE_IS_INCLUDE = 1,
    MODE_IS_EXCLUDE,
    CHANGE_TO_INCLUDE_MODE,
    CHANGE_TO_EXCLUDE_MODE,
    ALLOW_NEW_SOURCES,
    BLOCK_OLD_SOURCES
};

struct igmp3_membership_query {
    uint8_t flags;
    uint8_t qqic;
    uint16_t nsources;
    uint32_t *src_addrs;
};

struct igmp3_membership_report {
    uint8_t type;
    uint8_t aux_data_len;
    uint8_t nsources;
    uint32_t mcast_addr;
    uint32_t *src_addrs;
};

struct igmp_info {
    uint8_t type;
    uint8_t max_resp_time; /* reserved for igmp3 membership_report*/
    uint16_t checksum;

    /* for igmp3 membership_report the least significant 16 bits of group_addr are used to
       indicate number of group records and the rest are reserved */
    union {
        uint32_t group_addr;
        uint16_t ngroups;
    };
    union {
        struct igmp3_membership_query *query;
        struct igmp3_membership_report *records;
    };
};

void register_igmp(void);
char *get_igmp_type(uint8_t type);
struct packet_flags *get_igmp_query_flags(void);
int get_igmp_query_flags_size(void);
char *get_igmp_group_record_type(uint8_t type);

#endif
