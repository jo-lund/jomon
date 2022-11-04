#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/igmp.h>
#include <stddef.h>
#include <arpa/inet.h>
#include "packet_igmp.h"
#include "packet_ip.h"
#include "../error.h"
#include "../util.h"

#define IGMP_HDR_LEN 8

extern void add_igmp_information(void *w, void *sw, void *data);
extern void print_igmp(char *buf, int n, void *data);
static packet_error handle_igmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                                struct packet_data *pdata);

static struct packet_flags query_flags[] = {
    { "Reserved", 4, NULL },
    { "S", 1, NULL },
    { "QRV", 3, NULL }
};

static struct protocol_info igmp_prot = {
    .short_name = "IGMP",
    .long_name = "Internet Group Management Protocol",
    .decode = handle_igmp,
    .print_pdu = print_igmp,
    .add_pdu = add_igmp_information
};

void register_igmp(void)
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
 */
packet_error handle_igmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    if (n < IGMP_HDR_LEN)
        return UNK_PROTOCOL;

    struct igmp_info *igmp;

    igmp = mempool_calloc(1, struct igmp_info);
    pdata->data = igmp;
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    igmp->type = buffer[0];
    igmp->max_resp_time = buffer[1];
    igmp->checksum = get_uint16be(&buffer[2]);
    buffer += 4;
    if (igmp->type == IGMP_v3_HOST_MEMBERSHIP_REPORT)
        igmp->ngroups = get_uint16be(&buffer[2]);
    else
        igmp->group_addr = get_uint32le(buffer);
    buffer += 4;
    n -= 8;
    switch (igmp->type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        if (n >= 4) {
            igmp->query = mempool_alloc(sizeof(*igmp->query));
            igmp->query->flags = buffer[0];
            igmp->query->qqic = buffer[1];
            igmp->query->nsources = get_uint16be(&buffer[2]);
            buffer += 4;
            n -= 4;
            if (n < 4)
                break;
            if (igmp->query->nsources * 4 > n) {
                pdata->error = create_error_string("Too many source addresses (%d) in query",
                                                   igmp->query->nsources);
                return DECODE_ERR;
            }
            igmp->query->src_addrs = mempool_alloc(igmp->query->nsources * 4);
            parse_ipv4_addr(igmp->query->src_addrs, igmp->query->nsources, &buffer, n);
        }
        break;
    case IGMP_v3_HOST_MEMBERSHIP_REPORT:
        if (n > 0 && igmp->ngroups > 0) {
            if (igmp->ngroups > n) {
                pdata->error = create_error_string("Too many group records (%d)", igmp->ngroups);
                return DECODE_ERR;
            }
            igmp->records = mempool_alloc(sizeof(*igmp->records) * igmp->ngroups);
            for (int i = 0; i < igmp->ngroups && n >= 8; i++) {
                igmp->records[i].type = buffer[0];
                igmp->records[i].aux_data_len = buffer[1];
                igmp->records[i].nsources = get_uint16be(&buffer[2]);
                buffer += 4;
                igmp->records[i].mcast_addr = read_uint32le(&buffer);
                n -= 8;
                if (n < 4)
                    break;
                if (igmp->records[i].nsources * 4 > n) {
                    pdata->error = create_error_string("Too many source addresses (%d) in group record",
                                                       igmp->records[i].nsources);
                    return DECODE_ERR;
                }
                igmp->records[i].src_addrs = mempool_alloc(igmp->records[i].nsources * 4);
                n = parse_ipv4_addr(igmp->records[i].src_addrs, igmp->records[i].nsources, &buffer, n);
            }
        }
        break;
    default:
        break;
    }
    return NO_ERR;
}

char *get_igmp_type(uint8_t type)
{
    switch (type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        return "Membership query";
    case IGMP_v1_HOST_MEMBERSHIP_REPORT:
        return "Version 1 Membership report";
    case IGMP_v2_HOST_MEMBERSHIP_REPORT:
        return "Version 2 Membership report";
    case IGMP_v3_HOST_MEMBERSHIP_REPORT:
        return "Version 3 Membership report";
    case IGMP_HOST_LEAVE_MESSAGE:
        return "Leave group";
    default:
        return NULL;
    }
}

struct packet_flags *get_igmp_query_flags(void)
{
    return query_flags;
}

int get_igmp_query_flags_size(void)
{
    return ARRAY_SIZE(query_flags);
}

char *get_igmp_group_record_type(uint8_t type)
{
    switch (type) {
    case MODE_IS_INCLUDE:
        return "Mode is include";
    case MODE_IS_EXCLUDE:
        return "Mode is exclude";
    case CHANGE_TO_INCLUDE_MODE:
        return "Change to include mode";
    case CHANGE_TO_EXCLUDE_MODE:
        return "Change to exclude mode";
    case ALLOW_NEW_SOURCES:
        return "Allow new sources";
    case BLOCK_OLD_SOURCES:
        return "Block old sources";
    default:
        return NULL;
    }
}
