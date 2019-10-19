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
                          int dlen, struct application_info *adu);

static struct protocol_info nbds_prot = {
    .short_name = "NBDS",
    .long_name = "NetBIOS Datagram Service",
    .port = NBDS,
    .decode = handle_nbds,
    .print_pdu = print_nbds,
    .add_pdu = add_nbds_information
};

void register_nbds()
{
    register_protocol(&nbds_prot, LAYER4);
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
                         void *data)
{
    if (n < NBDS_HDRLEN) return NBDS_ERR;

    struct application_info *adu = data;
    unsigned char *ptr;
    int plen = n;

    ptr = buffer;
    adu->nbds = mempool_pealloc(sizeof(struct nbds_info));
    adu->nbds->msg_type = ptr[0];
    adu->nbds->flags = ptr[1];
    adu->nbds->dgm_id = get_uint16be(ptr + 2);
    adu->nbds->source_ip = get_uint32le(ptr + 4);
    adu->nbds->source_port = get_uint16be(ptr + 8);
    ptr += NBDS_HDRLEN;
    plen -= NBDS_HDRLEN;

    switch (adu->nbds->msg_type) {
    case NBDS_DIRECT_UNIQUE:
    case NBDS_DIRECT_GROUP:
    case NBDS_BROADCAST:
        if ((plen = parse_datagram(buffer, n, &ptr, plen, adu)) == -1) {
            return NBDS_ERR;
        }
        break;
    case NBDS_ERROR:
        adu->nbds->msg.error_code = ptr[0];
        break;
    case NBDS_QUERY_REQUEST:
    case NBDS_POSITIVE_QUERY_RESPONSE:
    case NBDS_NEGATIVE_QUERY_RESPONSE:
    {
        char name[DNS_NAMELEN];

        if (parse_dns_name(buffer, n, ptr, plen, name) == -1) {
            return NBDS_ERR;
        }
        decode_nbns_name(adu->nbds->msg.dest_name, name);
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
                   struct application_info *adu)

{
    unsigned char *ptr = *data;
    struct nbds_datagram *dgm;
    char name[DNS_NAMELEN];
    uint16_t len;
    int name_len;

    dgm = mempool_pealloc(sizeof(struct nbds_datagram));
    adu->nbds->msg.dgm = dgm;
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
    len = name_len;
    if ((name_len = parse_dns_name(buffer, n, ptr, dlen, name)) == -1) {
        return -1;
    }
    decode_nbns_name(dgm->dest_name, name);
    len += name_len;
    ptr += name_len;
    dlen -= name_len;
    if (dgm->dgm_length > len) {
        dgm->smb = mempool_pealloc(sizeof(struct smb_info));
        handle_smb(ptr, dgm->dgm_length - len, dgm->smb);
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
