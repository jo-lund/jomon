#include <string.h>
#include "packet_nbds.h"
#include "packet.h"
#include "packet_dns.h"
#include "packet_smb.h"
#include "../util.h"

#define NBDS_HDRLEN 10

static char *node_type[] = { "B node", "P node", "M node", "NBDD" };

struct packet_flags nbds_flags[] = {
    { "Reserved", 4, NULL },
    { "Source End-node type:", 2, node_type },
    { "First flag", 1, NULL },
    { "More flag", 1, NULL }
};


extern void print_nbds(char *buf, int n, void *data);
extern void add_nbds_information(void *widget, void *subwidget, void *data);
static int parse_datagram(unsigned char *buffer, int n, unsigned char **data,
                          int dlen, struct nbds_info *nbds, struct packet_data *pdata);

static struct protocol_info nbds_prot = {
    .short_name = "NBDS",
    .long_name = "NetBIOS Datagram Service",
    .decode = handle_nbds,
    .print_pdu = print_nbds,
    .add_pdu = add_nbds_information
};

void register_nbds()
{
    register_protocol(&nbds_prot, PORT, NBDS);
}

/*
 * NBDS header:
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   MSG_TYPE    |     FLAGS     |           DGM_ID              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           SOURCE_IP                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          SOURCE_PORT          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * rfc1002 includes two more fields in its header, the DGM_LENGTH and PACKET_OFFSET
 * fields. Theses fields are actually specific to messages that carry a data
 * payload: the DIRECT_UNIQUE, DIRECT_GROUP, and BROADCAST DATAGRAM messages.
 */
packet_error handle_nbds(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    if (n < NBDS_HDRLEN) return DECODE_ERR;

    struct nbds_info *nbds;
    unsigned char *ptr;
    int plen = n;

    ptr = buffer;
    nbds = mempool_pealloc(sizeof(struct nbds_info));
    pdata->data = nbds;
    pdata->len = n;
    nbds->msg_type = ptr[0];
    nbds->flags = ptr[1];
    nbds->dgm_id = get_uint16be(ptr + 2);
    nbds->source_ip = get_uint32le(ptr + 4);
    nbds->source_port = get_uint16be(ptr + 8);
    ptr += NBDS_HDRLEN;
    plen -= NBDS_HDRLEN;

    switch (nbds->msg_type) {
    case NBDS_DIRECT_UNIQUE:
    case NBDS_DIRECT_GROUP:
    case NBDS_BROADCAST:
        if ((plen = parse_datagram(buffer, n, &ptr, plen, nbds, pdata)) == -1) {
            return DECODE_ERR;
        }
        break;
    case NBDS_ERROR:
        nbds->msg.error_code = ptr[0];
        break;
    case NBDS_QUERY_REQUEST:
    case NBDS_POSITIVE_QUERY_RESPONSE:
    case NBDS_NEGATIVE_QUERY_RESPONSE:
    {
        char name[DNS_NAMELEN];

        if (parse_dns_name(buffer, n, ptr, plen, name) == -1) {
            return DECODE_ERR;
        }
        decode_nbns_name(nbds->msg.dest_name, name);
        break;
    }
    default:
        break;
    }
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    return NO_ERR;
}

int parse_datagram(unsigned char *buffer, int n, unsigned char **data, int dlen,
                   struct nbds_info *nbds, struct packet_data *pdata)

{
    unsigned char *ptr = *data;
    struct nbds_datagram *dgm;
    char name[DNS_NAMELEN];
    uint16_t tot_name_len;
    int name_len;

    dgm = mempool_pealloc(sizeof(struct nbds_datagram));
    nbds->msg.dgm = dgm;
    dgm->dgm_length = get_uint16be(ptr);
    dgm->packet_offset = get_uint16be(ptr + 2);
    ptr += 4;
    dlen -= 4;
    if ((name_len = parse_dns_name(buffer, n, ptr, dlen, name)) == -1) {
        return -1;
    }
    decode_nbns_name(dgm->src_name, name);
    ptr += name_len;
    dlen -= name_len;
    tot_name_len = name_len;
    if ((name_len = parse_dns_name(buffer, n, ptr, dlen, name)) == -1) {
        return -1;
    }
    decode_nbns_name(dgm->dest_name, name);
    tot_name_len += name_len;
    ptr += name_len;
    dlen -= name_len;
    pdata->len = tot_name_len + 4 + NBDS_HDRLEN;
    if (dgm->dgm_length > tot_name_len) {
        struct protocol_info *pinfo;

        pdata->id = get_protocol_id(PORT, SMB);
        if ((pinfo = get_protocol(pdata->id))) {
            pdata->next = mempool_pealloc(sizeof(struct packet_data));
            memset(pdata->next, 0, sizeof(struct packet_data));
            pinfo->decode(pinfo, ptr, dgm->dgm_length - (tot_name_len - 4), pdata->next);
        }
    }
    *data = ptr;
    return dlen;
}

struct packet_flags *get_nbds_flags()
{
    return nbds_flags;
}

int get_nbds_flags_size()
{
    return sizeof(nbds_flags) / sizeof(struct packet_flags);
}

char *get_nbds_message_type(uint8_t type)
{
    switch (type) {
    case NBDS_DIRECT_UNIQUE:
        return "Direct unique datagram";
    case NBDS_DIRECT_GROUP:
        return "Direct group datagram";
    case NBDS_BROADCAST:
        return "Broadcast datagram";
    case NBDS_ERROR:
        return "Datagram error";
    case NBDS_QUERY_REQUEST:
        return "Datagram query request";
    case NBDS_POSITIVE_QUERY_RESPONSE:
        return "Datagram positive query response";
    case NBDS_NEGATIVE_QUERY_RESPONSE:
        return "Datagram negative query response";
    default:
        return NULL;
    }
}
