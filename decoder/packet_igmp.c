#include <netinet/igmp.h>
#include <stddef.h>
#include <arpa/inet.h>
#include "packet_igmp.h"
#include "packet_ip.h"
#include "../error.h"

#define IGMP_HDR_LEN 8


extern void add_igmp_information(void *w, void *sw, void *data);
extern void print_igmp(char *buf, int n, void *data);

static struct protocol_info igmp_prot = {
    .short_name = "IGMP",
    .long_name = "Internet Group Management Protocol",
    .decode = handle_igmp,
    .print_pdu = print_igmp,
    .add_pdu = add_igmp_information
};

void register_igmp()
{
    register_protocol(&igmp_prot, IP_PROTOCOL, IPPROTO_IGMP);
}

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
packet_error handle_igmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    if (n < IGMP_HDR_LEN) return DECODE_ERR;

    struct igmp *igmp;
    struct igmp_info *info;

    info = mempool_pealloc(sizeof(struct igmp_info));
    pdata->data = info;
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    igmp = (struct igmp *) buffer;
    info->type = igmp->igmp_type;
    info->max_resp_time = igmp->igmp_code;
    info->checksum = ntohs(igmp->igmp_cksum);
    info->group_addr = igmp->igmp_group.s_addr;
    return NO_ERR;
}

char *get_igmp_type(uint8_t type)
{
    switch (type) {
    case IGMP_MEMBERSHIP_QUERY:
        return "Membership query";
    case IGMP_V1_MEMBERSHIP_REPORT:
        return "Version 1 Membership report";
    case IGMP_V2_MEMBERSHIP_REPORT:
        return "Version 2 Membership report";
    case IGMP_V2_LEAVE_GROUP:
        return "Leave group";
    case IGMP_PIM:
    default:
        return NULL;
    }
}
