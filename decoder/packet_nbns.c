#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "packet_nbns.h"
#include "packet_dns.h"
#include "packet.h"

static struct packet_flags nbns_flags[] = {
    { "Authoritative answer", 1, NULL },
    { "Truncation", 1, NULL },
    { "Recursion desired", 1, NULL },
    { "Recursion available", 1, NULL },
    { "", 2, NULL },
    { "Broadcast/Multicast", 1, NULL }
};

static char *nb_name[] = { "Unique NetBIOS name", "Group NetBIOS name" };
static char *nb_ont[] = { "B node", "P node", "M node", "Reserved" };

static struct packet_flags nbns_nb_flags[] = {
    { "Name Flag:", 1, nb_name },
    { "Owner Node Type:", 2, nb_ont }
};

static void parse_nbns_record(int i, unsigned char *buffer, int n, unsigned char **ptr, struct nbns_info *info);

/*
 * NBNS serves much of the same purpose as DNS, and the NetBIOS Name Service
 * packets follow the packet structure defined in DNS.
 *
 * NBNS header:
 *
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         NAME_TRN_ID           | OPCODE  |   NM_FLAGS  | RCODE |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          QDCOUNT              |           ANCOUNT             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          NSCOUNT              |           ARCOUNT             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * NM_FLAGS:
 *
 *   0   1   2   3   4   5   6
 * +---+---+---+---+---+---+---+
 * |AA |TC |RD |RA | 0 | 0 | B |
 * +---+---+---+---+---+---+---+
 */
packet_error handle_nbns(unsigned char *buffer, int n, struct application_info *info)
{
    if (n < DNS_HDRLEN) return NBNS_ERR;

    unsigned char *ptr = buffer;

    info->nbns = malloc(sizeof(struct nbns_info));
    info->nbns->id = ptr[0] << 8 | ptr[1];
    info->nbns->opcode = (ptr[2] & 0x78) >> 3;
    info->nbns->aa = (ptr[2] & 0x04) >> 2;
    info->nbns->tc = (ptr[2] & 0x02) >> 1;
    info->nbns->rd = ptr[2] & 0x01;
    info->nbns->ra = (ptr[3] & 0x80) >> 7;
    info->nbns->broadcast = (ptr[3] & 0x10) >> 4;
    info->nbns->rcode = ptr[3] & 0x0f;
    for (int i = 0, j = 4; i < 4; i++, j += 2) {
        info->nbns->section_count[i] = ptr[j] << 8 | ptr[j + 1];
    }
    info->nbns->record = NULL;

    /*
     * the first bit in the opcode field specifies whether it is a request (0)
     * or a response (1)
     */
    info->nbns->r = (ptr[2] & 0x80U) >> 7;

    if (info->nbns->r) { /* response */
        if (info->nbns->section_count[QDCOUNT] != 0) { /* QDCOUNT is always 0 for responses */
            free(info->nbns);
            return NBNS_ERR;
        }
        ptr += DNS_HDRLEN;

        /* Answer/Authority/Additional records sections */
        int i = ANCOUNT;
        int num_records = 0;
        while (i < 4) {
            num_records += info->nbns->section_count[i++];
        }
        info->nbns->record = malloc(num_records * sizeof(struct nbns_rr));
        for (int j = 0; j < num_records; j++) {
            parse_nbns_record(j, buffer, n, &ptr, info->nbns);
        }
    } else { /* request */
        if (info->nbns->aa) { /* authoritative answer is only to be set in responses */
            free(info->nbns);
            return NBNS_ERR;
        }
        if (info->nbns->section_count[QDCOUNT] == 0) { /* QDCOUNT must be non-zero for requests */
            free(info->nbns);
            return NBNS_ERR;
        }
        ptr += DNS_HDRLEN;

        /* QUESTION section */
        char name[DNS_NAMELEN];
        ptr += parse_dns_name(buffer, n, ptr, name);
        decode_nbns_name(info->nbns->question.qname, name);
        info->nbns->question.qtype = ptr[0] << 8 | ptr[1];
        info->nbns->question.qclass = ptr[2] << 8 | ptr[3];
        ptr += 4; /* skip qtype and qclass */

        /* Additional records section */
        if (info->nbns->section_count[ARCOUNT]) {
            info->nbns->record = malloc(sizeof(struct nbns_rr));
            parse_nbns_record(0, buffer, n, &ptr, info->nbns);
        }
    }
    pstat[PROT_NBNS].num_packets++;
    pstat[PROT_NBNS].num_bytes += n;
    return NO_ERR;
}

/*
 * The 16 byte NetBIOS name is mapped into a 32 byte wide field using a
 * reversible, half-ASCII, biased encoding, cf. RFC 1001, First-level encoding
 */
void decode_nbns_name(char *dest, char *src)
{
    for (int i = 0; i < 16; i++) {
        dest[i] = (src[2*i] - 'A') << 4 | (src[2*i + 1] - 'A');
    }
    // TODO: Fix this properly
    int c = 14;
    while (c && isspace(dest[c])) { /* remove trailing whitespaces */
        c--;
    }
    dest[c + 1] = '\0';
}

/*
 * Parse a NBNS resource record.
 * int i is the resource record index.
 */
void parse_nbns_record(int i, unsigned char *buffer, int n, unsigned char **ptr, struct nbns_info *nbns)
{
    int rdlen;
    char name[DNS_NAMELEN];

    *ptr += parse_dns_name(buffer, n, *ptr, name);
    decode_nbns_name(nbns->record[i].rrname, name);
    nbns->record[i].rrtype = (*ptr)[0] << 8 | (*ptr)[1];
    nbns->record[i].rrclass = (*ptr)[2] << 8 | (*ptr)[3];
    nbns->record[i].ttl = (*ptr)[4] << 24 | (*ptr)[5] << 16 | (*ptr)[6] << 8 | (*ptr)[7];
    rdlen = (*ptr)[8] << 8 | (*ptr)[9];
    *ptr += 10; /* skip to rdata field */

    switch (nbns->record[i].rrtype) {
    case NBNS_NB:
        if (rdlen >= 6) {
            nbns->record[i].rdata.nb.g = ((*ptr)[0] & 0x80U) >> 7;
            nbns->record[i].rdata.nb.ont = ((*ptr)[0] & 0x60) >> 5;
            rdlen -= 2;
            (*ptr) += 2;
            for (int j = 0, k = 0; k < rdlen && k < MAX_NBNS_ADDR * 4 ; j++, k += 4) {
                nbns->record[i].rdata.nb.address[j] =
                    (*ptr)[k] << 24 | (*ptr)[k + 1] << 16 | (*ptr)[k + 2] << 8 | (*ptr)[k + 3];
            }
            nbns->record[i].rdata.nb.num_addr = rdlen / 4;
        }
        *ptr += rdlen;
        break;
    case NBNS_NS:
    {
        char name[DNS_NAMELEN];

        *ptr += parse_dns_name(buffer, n, *ptr, name);
        decode_nbns_name(nbns->record[i].rdata.nsdname, name);
        break;
    }
    case NBNS_A:
        if (rdlen == 4) {
            nbns->record[i].rdata.nsdipaddr =
                (*ptr)[0] << 24 | (*ptr)[1] << 16 | (*ptr)[2] << 8 | (*ptr)[3];
        }
        *ptr += rdlen;
        break;
    case NBNS_NBSTAT:
    {
        uint8_t num_names;

        num_names = (*ptr)[0];
        (*ptr)++;
        for (int j = 0; j < num_names; j++) {
            memcpy(nbns->record[i].rdata.nbstat[j].node_name, (*ptr), NBNS_NAMELEN);
            nbns->record[i].rdata.nbstat[j].node_name[NBNS_NAMELEN] = '\0';
            *ptr += NBNS_NAMELEN;
            nbns->record[i].rdata.nbstat[j].name_flags = (*ptr)[0] << 8 | (*ptr)[1];
            *ptr += 2;
        }
        // TODO: Include statistics
        break;
    }
    case NBNS_NULL:
    default:
        *ptr += rdlen;
        break;
    }
}

char *get_nbns_opcode(uint8_t opcode)
{
    switch (opcode) {
    case NBNS_QUERY:
        return "Query";
    case NBNS_REGISTRATION:
        return "Registration";
    case NBNS_RELEASE:
        return "Release";
    case NBNS_WACK:
        return "WACK";
    case NBNS_REFRESH:
        return "Refresh";
    default:
        return "";
    }
}

char *get_nbns_rcode(uint8_t rcode)
{
    switch (rcode) {
    case NBNS_NO_ERROR:
        return "No error";
    case NBNS_FMT_ERR:
        return "Format Error. Request was invalidly formatted";
    case NBNS_SRV_ERR:
        return "Server failure. Problem with NBNS, cannot process name";
    case NBNS_IMP_ERR:
        return "Unsupported request error";
    case NBNS_RFS_ERR:
        return "Refused error";
    case NBNS_ACT_ERR:
        return "Active error. Name is owned by another node";
    case NBNS_CFT_ERR:
        return "Name in conflict error";
    default:
        return "";
    }
}

char *get_nbns_type(uint16_t qtype)
{
    switch (qtype) {
    case NBNS_A:
        return "A";
    case NBNS_NS:
        return "NS";
    case NBNS_NULL:
        return "NULL";
    case NBNS_NB:
        return "NB";
    case NBNS_NBSTAT:
        return "NBSTAT";
    default:
        return "";
    }
}

char *get_nbns_type_extended(uint16_t qtype)
{
    switch (qtype) {
    case NBNS_A:
        return "A (IP address)";
    case NBNS_NS:
        return "NS (Name Server";
    case NBNS_NULL:
        return "NULL";
    case NBNS_NB:
        return "NB (NetBIOS general Name Service)";
    case NBNS_NBSTAT:
        return "NBSTAT (NetBIOS NODE STATUS)";
    default:
        return "";
    }
}

char *get_nbns_node_type(uint8_t type)
{
    switch (type) {
    case NBNS_BNODE:
        return "B Node";
    case NBNS_PNODE:
        return "P Node";
    case NBNS_MNODE:
        return "M Node";
    default:
        return "";
    }
}

struct packet_flags *get_nbns_flags()
{
    return nbns_flags;
}

struct packet_flags *get_nbns_nb_flags()
{
    return nbns_nb_flags;
}
