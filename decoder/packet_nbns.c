#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "packet_nbns.h"
#include "packet_dns.h"
#include "packet.h"
#include "../util.h"

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

extern void print_nbns(char *buf, int n, void *data);
extern void add_nbns_information(void *widget, void *subwidget, void *data);
static int parse_nbns_record(int i, unsigned char *buffer, int n, unsigned char **data,
                             int dlen, struct nbns_info *info);

static struct protocol_info nbns_prot = {
    .short_name = "NBNS",
    .long_name = "NetBIOS Name Service",
    .decode = handle_nbns,
    .print_pdu = print_nbns,
    .add_pdu = add_nbns_information
};

void register_nbns()
{
    register_protocol(&nbns_prot, PORT, NBNS);
}

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
packet_error handle_nbns(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    if (n < DNS_HDRLEN) return DECODE_ERR;

    unsigned char *ptr = buffer;
    int plen = n;
    struct nbns_info *nbns;

    nbns = mempool_alloc(sizeof(struct nbns_info));
    pdata->data = nbns;
    pdata->len = n;
    nbns->id = ptr[0] << 8 | ptr[1];
    nbns->opcode = (ptr[2] & 0x78) >> 3;
    nbns->aa = (ptr[2] & 0x04) >> 2;
    nbns->tc = (ptr[2] & 0x02) >> 1;
    nbns->rd = ptr[2] & 0x01;
    nbns->ra = (ptr[3] & 0x80) >> 7;
    nbns->broadcast = (ptr[3] & 0x10) >> 4;
    nbns->rcode = ptr[3] & 0x0f;
    for (int i = 0, j = 4; i < 4; i++, j += 2) {
        nbns->section_count[i] = ptr[j] << 8 | ptr[j + 1];
    }
    nbns->record = NULL;

    /*
     * the first bit in the opcode field specifies whether it is a request (0)
     * or a response (1)
     */
    nbns->r = (ptr[2] & 0x80U) >> 7;

    if (nbns->r) { /* response */
        if (nbns->section_count[QDCOUNT] != 0) { /* QDCOUNT is always 0 for responses */
            return DECODE_ERR;
        }
        ptr += DNS_HDRLEN;
        plen -= DNS_HDRLEN;

        /* Answer/Authority/Additional records sections */
        int i = ANCOUNT;
        int num_records = 0;
        while (i < 4) {
            num_records += nbns->section_count[i++];
        }
        nbns->record = mempool_alloc(num_records * sizeof(struct nbns_rr));
        for (int j = 0; j < num_records; j++) {
            int len = parse_nbns_record(j, buffer, n, &ptr, plen, nbns);

            if (len == -1) return DECODE_ERR;
            plen -= len;
        }
    } else { /* request */
        if (nbns->aa) { /* authoritative answer is only to be set in responses */
            return DECODE_ERR;
        }
        if (nbns->section_count[QDCOUNT] == 0) { /* QDCOUNT must be non-zero for requests */
            return DECODE_ERR;
        }
        ptr += DNS_HDRLEN;
        plen -= DNS_HDRLEN;

        /* QUESTION section */
        char name[DNS_NAMELEN];
        int len = parse_dns_name(buffer, n, ptr, plen, name);

        if (len == -1) return DECODE_ERR;
        ptr += len;
        plen -= len;
        decode_nbns_name(nbns->question.qname, name);
        nbns->question.qtype = ptr[0] << 8 | ptr[1];
        nbns->question.qclass = ptr[2] << 8 | ptr[3];
        ptr += 4; /* skip qtype and qclass */
        plen -= 4;

        /* Additional records section */
        if (nbns->section_count[ARCOUNT] > (unsigned int) n) {
            return DECODE_ERR;
        }
        if (nbns->section_count[ARCOUNT]) {
            nbns->record = mempool_alloc(nbns->section_count[ARCOUNT] *
                                           sizeof(struct nbns_rr));
            for (unsigned int i = 0; i < nbns->section_count[ARCOUNT]; i++) {
                int len = parse_nbns_record(i, buffer, n, &ptr, plen, nbns);

                if (len == -1) return DECODE_ERR;
                plen -= len;
            }
        }
    }
    pinfo->num_packets++;
    pinfo->num_bytes += n;
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
int parse_nbns_record(int i, unsigned char *buffer, int n, unsigned char **data,
                      int dlen, struct nbns_info *nbns)
{
    unsigned char *ptr = *data;
    int rdlen;
    char name[DNS_NAMELEN];
    int len;

    len = parse_dns_name(buffer, n, ptr, dlen, name);
    if (len == -1) return -1;
    ptr += len;
    decode_nbns_name(nbns->record[i].rrname, name);
    nbns->record[i].rrtype = get_uint16be(ptr);
    nbns->record[i].rrclass = get_uint16be(ptr + 2);
    nbns->record[i].ttl = get_uint32be(ptr + 4);
    rdlen = get_uint16be(ptr + 8);
    ptr += 10; /* skip to rdata field */
    dlen -= 10;
    if (rdlen > dlen) return -1;
    len += 10 + rdlen;

    switch (nbns->record[i].rrtype) {
    case NBNS_NB:
        if (rdlen >= 6) {
            nbns->record[i].rdata.nb.g = (ptr[0] & 0x80U) >> 7;
            nbns->record[i].rdata.nb.ont = (ptr[0] & 0x60) >> 5;
            rdlen -= 2;
            ptr += 2;
            for (int j = 0, k = 0; k < rdlen && k < MAX_NBNS_ADDR * 4 ; j++, k += 4) {
                nbns->record[i].rdata.nb.address[j] = get_uint32le(ptr + k);
            }
            nbns->record[i].rdata.nb.num_addr = rdlen / 4;
        }
        ptr += rdlen;
        break;
    case NBNS_NS:
    {
        char name[DNS_NAMELEN];
        int name_len = parse_dns_name(buffer, n, ptr, dlen, name);

        if (name_len == -1) return -1;
        ptr += name_len;
        decode_nbns_name(nbns->record[i].rdata.nsdname, name);
        break;
    }
    case NBNS_A:
        if (rdlen == 4) {
            nbns->record[i].rdata.nsdipaddr = get_uint32le(ptr);
        }
        ptr += rdlen;
        break;
    case NBNS_NBSTAT:
    {
        uint8_t num_names;

        num_names = ptr[0];
        if (num_names > MAX_NBNS_NAMES) {
            num_names = MAX_NBNS_NAMES;
        }
        ptr++;
        for (int j = 0; j < num_names; j++) {
            memcpy(nbns->record[i].rdata.nbstat[j].node_name, ptr, NBNS_NAMELEN);
            nbns->record[i].rdata.nbstat[j].node_name[NBNS_NAMELEN-1] = '\0';
            ptr += NBNS_NAMELEN;
            nbns->record[i].rdata.nbstat[j].name_flags = ptr[0] << 8 | ptr[1];
            ptr += 2;
        }
        // TODO: Include statistics
        break;
    }
    case NBNS_NULL:
    default:
        ptr += rdlen;
        break;
    }
    return len;
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

int get_nbns_flags_size()
{
    return sizeof(nbns_flags) / sizeof(struct packet_flags);
}

struct packet_flags *get_nbns_nb_flags()
{
    return nbns_nb_flags;
}

int get_nbns_nb_flags_size()
{
    return sizeof(nbns_nb_flags) / sizeof(struct packet_flags);
}
