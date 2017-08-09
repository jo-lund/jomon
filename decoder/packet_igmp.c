#include <linux/igmp.h>
#include <stddef.h>
#include <arpa/inet.h>
#include "packet_icmp.h"
#include "packet_ip.h"
#include "../error.h"

#define IGMP_HDR_LEN 8

/*
 * IGMP message format:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Type     | Max Resp Time |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Group Address                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Messages must be atleast 8 bytes.
 *
 * Message Type                  Destination Group
 * ------------                  -----------------
 * General Query                 All hosts (224.0.0.1)
 * Group-Specific Query          The group being queried
 * Membership Report             The group being reported
 * Leave Message                 All routers (224.0.0.2)
 *
 * 224.0.0.22 is the IGMPv3 multicast address.
 *
 * Max Resp Time specifies the maximum allowed time before sending a responding
 * report in units of 1/10 seconds. It is only meaningful in membership queries.
 * Default: 100 (10 seconds).
 *
 * Message query:
 * - A general query has group address field 0 and is sent to the all hosts
 *   multicast group (224.0.0.1)
 * - A group specific query must have a valid multicast group address
 * - The Query Interval is the interval between general queries sent by the
 *   querier. Default: 125 seconds.
 *
 * Group Address is the multicast address being queried when sending a
 * Group-Specific or Group-and-Source-Specific Query. The field is zeroed when
 * sending a General Query.
 *
 * TODO: Handle IGMPv3 membership query
 */
packet_error handle_igmp(unsigned char *buffer, int n, struct igmp_info *info)
{
    if (n < IGMP_HDR_LEN) return IGMP_ERR;

    struct igmphdr *igmp;

    pstat[PROT_IGMP].num_packets++;
    pstat[PROT_IGMP].num_bytes += n;
    igmp = (struct igmphdr *) buffer;
    info->type = igmp->type;
    info->max_resp_time = igmp->code;
    info->checksum = ntohs(igmp->csum);
    info->group_addr = igmp->group;
    return NO_ERR;
}

char *get_igmp_type(uint8_t type)
{
    switch (type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        return "Membership query";
    case IGMP_HOST_MEMBERSHIP_REPORT:
        return "Version 1 Membership report";
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
        return "Version 2 Membership report";
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
        return "Version 3 Membership report";
    case IGMP_HOST_LEAVE_MESSAGE:
        return "Leave group";
    case IGMP_PIM:
    default:
        return NULL;
    }
}
