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

static bool parse_datagram(unsigned char *buffer, int n, unsigned char **data,
                           struct application_info *adu);

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
packet_error handle_nbds(unsigned char *buffer, int n, struct application_info *adu)
{
    if (n < NBDS_HDRLEN) return NBDS_ERR;

    unsigned char *ptr;

    ptr = buffer;
    adu->nbds = malloc(sizeof(struct nbds_info));
    adu->nbds->msg_type = ptr[0];
    adu->nbds->flags = ptr[1];
    adu->nbds->dgm_id = get_uint16be(ptr + 2);
    adu->nbds->source_ip = get_uint32le(ptr + 4);
    adu->nbds->source_port = get_uint16be(ptr + 8);
    ptr += NBDS_HDRLEN;

    switch (adu->nbds->msg_type) {
    case NBDS_DIRECT_UNIQUE:
    case NBDS_DIRECT_GROUP:
    case NBDS_BROADCAST:
        parse_datagram(buffer, n, &ptr, adu);
        break;
    case NBDS_ERROR:
        adu->nbds->msg.error_code = ptr[0];
        break;
    case NBDS_QUERY_REQUEST:
    case NBDS_POSITIVE_QUERY_RESPONSE:
    case NBDS_NEGATIVE_QUERY_RESPONSE:
    {
        char name[DNS_NAMELEN];

        parse_dns_name(buffer, n, ptr, name);
        decode_nbns_name(adu->nbds->msg.dest_name, name);
        break;
    }
    default:
        break;
    }
    pstat[PROT_NBDS].num_packets++;
    pstat[PROT_NBDS].num_bytes += n;
    return NO_ERR;
}

bool parse_datagram(unsigned char *buffer, int n, unsigned char **data,
                    struct application_info *adu)

{
    unsigned char *ptr = *data;
    struct nbds_datagram *dgm;
    char name[DNS_NAMELEN];
    uint16_t len;
    uint16_t ptr_len;

    dgm = calloc(1, sizeof(struct nbds_datagram));
    dgm->dgm_length = get_uint16be(ptr);
    dgm->packet_offset = get_uint16be(ptr + 2);
    ptr += 4;
    ptr_len = parse_dns_name(buffer, n, ptr, name);
    decode_nbns_name(dgm->src_name, name);
    ptr += ptr_len;
    len = ptr_len;
    ptr_len = parse_dns_name(buffer, n, ptr, name);
    decode_nbns_name(dgm->dest_name, name);
    len += ptr_len;
    ptr += ptr_len;

    if (dgm->dgm_length > len) {
        dgm->smb = malloc(sizeof(struct smb_info));
        handle_smb(ptr, dgm->dgm_length - len, dgm->smb);
    }
    adu->nbds->msg.dgm = dgm;
    *data = ptr;
    return true;
}

void free_nbds_packet(struct nbds_info *nbds)
{
    if (nbds) {
        if (nbds->msg_type == NBDS_DIRECT_UNIQUE ||
            nbds->msg_type == NBDS_DIRECT_GROUP ||
            nbds->msg_type == NBDS_BROADCAST) {
            free(nbds->msg.dgm->smb);
            free(nbds->msg.dgm);
        }
        free(nbds);
    }
}

struct packet_flags *get_nbds_flags()
{
    return nbds_flags;
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
