#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packet_dns.h"
#include "packet.h"
#include "../util.h"
#include "dns_cache.h"

#define DNS_PTR_LEN 2

static struct packet_flags dns_flags[] = {
    { "Authoritative answer", 1, NULL },
    { "Truncation", 1, NULL },
    { "Recursion desired", 1, NULL },
    { "Recursion available", 1, NULL },
    { "Reserved", 1, NULL },
    { "Authentic data", 1, NULL },
    { "Checking disabled", 1, NULL }
};

static struct packet_flags llmnr_flags[] = {
    { "Conflict", 1, NULL },
    { "Truncation", 1, NULL },
    { "Tentative", 1, NULL },
    { "Reserved", 4, NULL }
};

extern void print_dns(char *buf, int n, void *data);
extern void add_dns_information(void *widget, void *subwidget, void *data);
static int parse_dns_record(int i, unsigned char *buffer, int n, unsigned char **data,
                             int dlen, struct dns_info *dns);
static int parse_dns_question(unsigned char *buffer, int n, unsigned char **data,
                              int dlen, struct dns_info *dns);
static char *parse_dns_txt(unsigned char **data);
static void free_opt_rr(void *data);
static bool parse_type_bitmaps(unsigned char **data, uint16_t rdlen,
                               struct dns_resource_record *record);

static struct protocol_info dns_prot = {
    .short_name = "DNS",
    .long_name = "Domain Name System",
    .decode = handle_dns,
    .print_pdu = print_dns,
    .add_pdu = add_dns_information
};

static struct protocol_info mdns_prot = {
    .short_name = "MDNS",
    .long_name = "Multicast DNS",
    .decode = handle_dns,
    .print_pdu = print_dns,
    .add_pdu = add_dns_information
};

static struct protocol_info llmnr_prot = {
    .short_name = "LLMNR",
    .long_name = "Link-Local Multicast Name Resolution",
    .decode = handle_dns,
    .print_pdu = print_dns,
    .add_pdu = add_dns_information
};

void register_dns()
{
    register_protocol(&dns_prot, LAYER4, DNS);
    register_protocol(&mdns_prot, LAYER4, MDNS);
    register_protocol(&llmnr_prot, LAYER4, LLMNR);
}

/*
 * Handle DNS messages. Will return false if not DNS.
 *
 * Format of message (http://tools.ietf.org/html/rfc1035):
 * +---------------------+
 * |        Header       |
 * +---------------------+
 * |       Question      | the question for the name server
 * +---------------------+
 * |        Answer       | RRs answering the question
 * +---------------------+
 * |      Authority      | RRs pointing toward an authority
 * +---------------------+
 * |      Additional     | RRs holding additional information
 * +---------------------+
 *
 * DNS header:
 *
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * ID: A 16 bit identifier assigned by the program that
       generates any kind of query. This identifier is copied
       the corresponding reply and can be used by the requester
       to match up replies to outstanding queries.
 * QR: query = 0, response = 1
 * RCODE: Response code - this 4 bit field is set as part of responses.
 * QDCOUNT: an unsigned 16 bit integer specifying the number of
 *          entries in the question section.
 * ANCOUNT: an unsigned 16 bit integer specifying the number of
 *          resource records in the answer section.
 * NSCOUNT: an unsigned 16 bit integer specifying the number of name
 *          server resource records in the authority records section.
 * ARCOUNT: an unsigned 16 bit integer specifying the number of
 *          resource records in the additional records section.
 */
packet_error handle_dns(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata)
{
    unsigned char *ptr = buffer;
    int plen = n;
    int num_records = 0;
    struct dns_info *dns;

    if (n < DNS_HDRLEN) return DECODE_ERR;
    dns = mempool_pealloc(sizeof(struct dns_info));
    pdata->data = dns;
    pdata->len = n;

    /*
     * According to RFC 1035, messages sent over TCP are prefixed with a two
     * byte length field
     */
    if (pdata->transport == IPPROTO_TCP) {
        dns->length = get_uint16be(ptr);
        ptr += 2;
    } else {
        dns->length = 0;
    }
    dns->id = ptr[0] << 8 | ptr[1];
    dns->qr = (ptr[2] & 0x80) >> 7;
    dns->opcode = (ptr[2] & 0x78) >> 3;
    if (pdata->id == LLMNR) {
        dns->llmnr_flags.c = (ptr[2] & 0x04) >> 2;
        dns->llmnr_flags.tc = (ptr[2] & 0x02) >> 1;
        dns->llmnr_flags.t = ptr[2] & 0x01;
    } else {
        dns->dns_flags.aa = (ptr[2] & 0x04) >> 2;
        dns->dns_flags.tc = (ptr[2] & 0x02) >> 1;
        dns->dns_flags.rd = ptr[2] & 0x01;
        dns->dns_flags.ra = (ptr[3] & 0x80) >> 7;
        dns->dns_flags.ad = (ptr[3] & 0x20) >> 5;
        dns->dns_flags.cd = (ptr[3] & 0x10) >> 4;
    }
    dns->rcode = ptr[3] & 0x0f;
    for (int i = 0, j = 4; i < 4; i++, j += 2) {
        dns->section_count[i] = ptr[j] << 8 | ptr[j + 1];
    }
    dns->question = NULL;
    dns->record = NULL;
    if (!dns->qr) {  /* DNS query */
        /*
         * ARCOUNT will typically be 0, 1, or 2, depending on whether EDNS0
         * (RFC 2671) or TSIG (RFC 2845) are used
         */
        if (dns->section_count[ARCOUNT] > 2) {
            return DECODE_ERR;
        }
    }
    ptr += DNS_HDRLEN;
    plen -= DNS_HDRLEN;

    /* QUESTION section */
    if (dns->section_count[QDCOUNT] > 0) {
        int len = parse_dns_question(buffer, n, &ptr, plen, dns);

        if (len == -1) {
            return DECODE_ERR;
        }
        plen -= len;
    }

    /* Answer/Authority/Additional records sections */
    for (int i = ANCOUNT; i < 4; i++) {
        num_records += dns->section_count[i];
    }
    if (num_records > n) {
        return DECODE_ERR;
    }
    if (num_records) {
        dns->record = mempool_pealloc(num_records * sizeof(struct dns_resource_record));
        for (int i = 0; i < num_records; i++) {
            int len = parse_dns_record(i, buffer, n, &ptr, plen, dns);

            if (len == -1) {
                return DECODE_ERR;
            }
            plen -= len;
        }
    }
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    return NO_ERR;
}

int parse_dns_question(unsigned char *buffer, int n, unsigned char **data,
                       int dlen, struct dns_info *dns)
{
    unsigned char *ptr = *data;
    int len = 0;

    if (dns->section_count[QDCOUNT] > dlen) {
        return -1;
    }
    dns->question = mempool_pealloc(dns->section_count[QDCOUNT] *
                           sizeof(struct dns_question));
    for (unsigned int i = 0; i < dns->section_count[QDCOUNT]; i++) {
        if ((len = parse_dns_name(buffer, n, ptr, dlen, dns->question[i].qname)) == -1) {
            return -1;
        }
        ptr += len;
        dns->question[i].qtype = ptr[0] << 8 | ptr[1];
        dns->question[i].qclass = ptr[2] << 8 | ptr[3];
        ptr += 4;
        len += 4;
    }
    *data = ptr;
    return len;
}

/*
 * Parse a DNS resource record.
 * int i is the recource record index.
 */
int parse_dns_record(int i, unsigned char *buffer, int n, unsigned char **data,
                     int dlen, struct dns_info *dns)
{
    int len;
    uint16_t rdlen;
    unsigned char *ptr = *data;

    len = parse_dns_name(buffer, n, ptr, dlen, dns->record[i].name);
    if (len == -1 || len > dlen) return -1;
    ptr += len;
    dlen -= len;
    dns->record[i].type = get_uint16be(ptr);
    dns->record[i].rrclass = get_uint16be(ptr + 2);
    dns->record[i].ttl = get_uint32be(ptr + 4);
    rdlen = get_uint16be(ptr + 8);
    if (rdlen > dlen) {
        return -1;
    }
    ptr += 10; /* skip to rdata field */
    dlen -= 10;
    len += 10 + rdlen;
    switch (dns->record[i].type) {
    case DNS_TYPE_A:
        if (rdlen == 4) {
            dns->record[i].rdata.address = get_uint32le(ptr);
            dns_cache_insert(dns->record[i].rdata.address, dns->record[i].name);
        }
        ptr += rdlen;
        break;
    case DNS_TYPE_NS:
    {
        int name_len = parse_dns_name(buffer, n, ptr, dlen, dns->record[i].rdata.nsdname);

        if (name_len == -1) return -1;
        ptr += name_len;
        break;
    }
    case DNS_TYPE_CNAME:
    {
        int name_len = parse_dns_name(buffer, n, ptr, dlen, dns->record[i].rdata.cname);

        if (name_len == -1) return -1;
        ptr += name_len;
        break;
    }
    case DNS_TYPE_SOA:
    {
        int name_len = parse_dns_name(buffer, n, ptr, dlen, dns->record[i].rdata.soa.mname);

        if (name_len == -1) return -1;
        ptr += name_len;
        name_len = parse_dns_name(buffer, n, ptr, dlen, dns->record[i].rdata.soa.rname);
        if (name_len == -1) return -1;
        ptr += name_len;
        dns->record[i].rdata.soa.serial = get_uint32be(ptr);
        dns->record[i].rdata.soa.refresh = get_uint32be(ptr + 4);
        dns->record[i].rdata.soa.retry = get_uint32be(ptr + 8);
        dns->record[i].rdata.soa.expire = get_uint32be(ptr + 12);
        dns->record[i].rdata.soa.minimum = get_uint32be(ptr + 16);
        ptr += 20;
        break;
    }
    case DNS_TYPE_PTR:
    {
        int name_len = parse_dns_name(buffer, n, ptr, dlen, dns->record[i].rdata.ptrdname);

        if (name_len == -1) return -1;
        ptr += name_len;
        break;
    }
    case DNS_TYPE_AAAA:
        if (rdlen == 16) {
            for (int j = 0; j < rdlen; j++) {
                dns->record[i].rdata.ipv6addr[j] = ptr[j];
            }
        }
        ptr += rdlen;
        break;
    case DNS_TYPE_HINFO:
        dns->record[i].rdata.hinfo.cpu = parse_dns_txt(&ptr);
        dns->record[i].rdata.hinfo.os = parse_dns_txt(&ptr);
        break;
    case DNS_TYPE_TXT:
    {
        int j = 0;

        dns->record[i].rdata.txt = list_init(&d_alloc);
        while (j < rdlen) {
            struct dns_txt_rr *rr;
            int len = 0;

            rr = mempool_pealloc(sizeof(struct dns_txt_rr));
            rr->txt = parse_dns_txt(&ptr);
            if (rr->txt) {
                len = strlen(rr->txt);
            }
            rr->len = len;
            j += len + 1;
            list_push_back(dns->record[i].rdata.txt, rr);
        }
        break;
    }
    case DNS_TYPE_MX:
    {
        int name_len;

        dns->record[i].rdata.mx.preference = get_uint16be(ptr);
        ptr += 2;
        name_len = parse_dns_name(buffer, n, ptr, dlen, dns->record[i].rdata.mx.exchange);
        if (name_len == -1) return -1;
        ptr += name_len;
        break;
    }
    case DNS_TYPE_SRV:
    {
        int name_len;

        dns->record[i].rdata.srv.priority = get_uint16be(ptr);
        dns->record[i].rdata.srv.weight = get_uint16be(ptr + 2);
        dns->record[i].rdata.srv.port = get_uint16be(ptr + 4);
        ptr += 6;
        name_len = parse_dns_name(buffer, n, ptr, dlen, dns->record[i].rdata.srv.target);
        if (name_len == -1) return -1;
        ptr += name_len;
        break;
    }
    case DNS_TYPE_OPT:
        dns->record[i].rdata.opt.rdlen = rdlen;
        if (rdlen) {
            dns->record[i].rdata.opt.data = mempool_pecopy(ptr, rdlen);
            ptr += rdlen;
        }
        break;
    case DNS_TYPE_NSEC:
    {
        int name_len;

        name_len = parse_dns_name(buffer, n, ptr, dlen, dns->record[i].rdata.nsec.nd_name);
        if (name_len == -1) return -1;
        ptr += name_len;
        if (!parse_type_bitmaps(&ptr, rdlen - name_len, &dns->record[i])) return -1;
        break;
    }
    default:
        ptr += rdlen;
        break;
    }
    *data = ptr; /* skip parsed dns record */
    return len;
}

/*
 * A domain name in a message can be represented as:
 *
 * - a sequence of labels ending in a zero octet
 * - a pointer
 * - a sequence of labels ending with a pointer
 *
 * Each label is represented as a one octet length field followed by that number
 * of octets. The high order two bits of the length field must be zero. Since
 * every domain name ends with the null label of the root, a domain name is
 * terminated by a length byte of zero.
 */
int parse_dns_name(unsigned char *buffer, int n, unsigned char *ptr, int plen, char name[])
{
    unsigned int len = 0; /* total length of name entry */
    unsigned int label_length = ptr[0];
    bool compression = false;
    unsigned int name_ptr_len = 0;
    int c = 0;

    if (!label_length) {
        return 1; /* length octet */
    }
    while (label_length && c < n) {
        /*
         * The max size of a label is 63 bytes, so a length with the first 2 bits
         * set to 11 indicates that the label is a pointer to a prior occurrence
         * of the same name. The pointer is an offset from the beginning of the
         * DNS message, i.e. the ID field of the header.
         *
         * The pointer takes the form of a two octet sequence:
         *
         * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         * | 1  1|                OFFSET                   |
         * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         */
        if ((label_length & 0xc0) == 0xc0) {
            uint16_t offset = (ptr[0] & 0x3f) << 8 | ptr[1];

            if (offset > n) return len + DNS_PTR_LEN;

            label_length = buffer[offset];
            ptr = buffer + offset; /* ptr will point to start of label */
            plen = n - offset;

            /*
             * Only update name_ptr_len if this is the first pointer encountered.
             * name_ptr_len must not include the ptrs in the prior occurrence of
             * the same name, i.e. if the name is a pointer to a sequence of
             * labels ending in a pointer.
             */
            if (!compression) {
                /*
                 * Total length of the name entry encountered so far + ptr. If name
                 * is just a pointer, len will be 0
                 */
                name_ptr_len = len + DNS_PTR_LEN;
                compression = true;
            }
        } else {
            if (label_length > plen || len > n || len + label_length >= DNS_NAMELEN) {
                return -1;
            }
            memcpy(name + len, ptr + 1, label_length);
            len += label_length;
            name[len++] = '.';
            ptr += label_length + 1; /* skip length octet + rest of label */
            plen -= (label_length + 1);
            label_length = ptr[0];
        }
        c++;
    }
    if (len) {
        name[len - 1] = '\0';
    }
    len++; /* add null label */
    return compression ? name_ptr_len : len;
}

/*
 * Parse DNS character strings. The strings are formatted as one byte length
 * field followed by that number of bytes.
 *
 * Returns the character string formatted as a C string, which needs to be freed
 * by the caller.
 */
char *parse_dns_txt(unsigned char **data)
{
    char *txt = NULL;
    uint8_t len;
    unsigned char *ptr = *data;

    len = *ptr++;
    if (len) {
        txt = mempool_pecopy0(ptr, len);
        ptr += len;
    }
    *data = ptr;
    return txt;
}

list_t *parse_dns_options(struct dns_resource_record *rr)
{
    list_t *opt;
    int length;
    unsigned char *ptr;

    opt = list_init(NULL);
    length = rr->rdata.opt.rdlen;
    ptr = rr->rdata.opt.data;
    while (length > 0) {
        struct dns_opt_rr *opt_rr;

        opt_rr = malloc(sizeof(struct dns_opt_rr));
        opt_rr->option_code = ptr[0] << 8 | ptr[1];
        opt_rr->option_length = ptr[2] << 8 | ptr[3];
        ptr += 4;
        length -= 4;
        opt_rr->data = malloc(opt_rr->option_length);
        memcpy(opt_rr->data, ptr, opt_rr->option_length);
        length -= opt_rr->option_length;
        ptr += opt_rr->option_length;
        list_push_back(opt, opt_rr);
    }
    return opt;
}

void free_dns_options(list_t *opt)
{
    list_free(opt, free_opt_rr);
}

void free_opt_rr(void *data)
{
    struct dns_opt_rr *rr = (struct dns_opt_rr *) data;

    free(rr->data);
    free(rr);
}

/*
 * The RR type space is split into 256 window blocks, each representing
 * the low-order 8 bits of the 16-bit RR type space. Each block that
 * has at least one active RR type is encoded using a single octet
 * window number (from 0 to 255), a single octet bitmap length (from 1
 * to 32) indicating the number of octets used for the window block's
 * bitmap, and up to 32 octets (256 bits) of bitmap.
 */
bool parse_type_bitmaps(unsigned char **data, uint16_t rdlen,
                        struct dns_resource_record *record)
{
    unsigned char *ptr = *data;
    unsigned int i = 0;
    uint8_t winnum;
    uint8_t maplen;

    record->rdata.nsec.num_types = 0;
    while (i < rdlen) {
        winnum = ptr[i];
        maplen = ptr[i + 1];
        if (maplen > rdlen) {
            mempool_pefree(mempool_pefinish());
            return false;
        }
        i += 2;
        for (unsigned int j = 0; j < maplen; j++) {
            for (unsigned int k = 0; k < 8; k++) {
                if (ptr[i + j] & (1 << (7 - k))) {
                    uint16_t type = winnum * 256 + k + (8 * j);

                    mempool_pegrow(&type, sizeof(uint16_t));
                    record->rdata.nsec.num_types++;
                }
            }
        }
        i += maplen;
    }
    ptr += i;
    record->rdata.nsec.types = mempool_pefinish();
    *data = ptr;
    return true;
}

char *get_dns_opcode(uint8_t opcode)
{
    switch (opcode) {
    case DNS_QUERY:
        return "Standard query";
    case DNS_IQUERY:
        return "Inverse query";
    case DNS_STATUS:
        return "Server status request";
    default:
        return "";
    }
}

char *get_dns_rcode(uint8_t rcode)
{
    switch (rcode) {
    case DNS_FORMAT_ERROR:
        return "Format error";;
    case DNS_SERVER_FAILURE:
        return "Server failure";;
    case DNS_NAME_ERROR:
        return "Name error";
    case DNS_NOT_IMPLEMENTED:
        return "Request not supported";
    case DNS_REFUSED:
        return "Operation refused";
    case DNS_NO_ERROR:
        return "No error condition";
    case DNS_YXDOMAIN:
        return "Name exists when it should not";
    case DNS_YXRRSET:
        return "RRset exists when it should not";
    case DNS_NXRRSET:
        return "RRset that should exist does not";
    case DNS_NOTAUTH:
        return "Not authoritative";
    case DNS_NOTZONE:
        return "Name not contained in zone";
    default:
        return "";
    }
}

char *get_dns_type(uint16_t type)
{
    switch (type) {
    case DNS_TYPE_A:
        return "A";
    case DNS_TYPE_NS:
        return "NS";
    case DNS_TYPE_CNAME:
        return "CNAME";
    case DNS_TYPE_SOA:
        return "SOA";
    case DNS_TYPE_PTR:
        return "PTR";
    case DNS_TYPE_MX:
        return "MX";
    case DNS_TYPE_AAAA:
        return "AAAA";
    case DNS_TYPE_HINFO:
        return "HINFO";
    case DNS_TYPE_TXT:
        return "TXT";
    case DNS_TYPE_SRV:
        return "SRV";
    case DNS_TYPE_OPT:
        return "OPT";
    case DNS_TYPE_DS:
        return "DS";
    case DNS_TYPE_RRSIG:
        return "RRSIG";
    case DNS_TYPE_NSEC:
        return "NSEC";
    case DNS_TYPE_DNSKEY:
        return "DNSKEY";
    case DNS_QTYPE_AXFR:
        return "AXFR";
    case DNS_QTYPE_STAR:
        return "*";
    default:
        return "";
    }
}

char *get_dns_type_extended(uint16_t type)
{
    switch (type) {
    case DNS_TYPE_A:
        return "A (host address)";
    case DNS_TYPE_NS:
        return "NS (authoritative name server)";
    case DNS_TYPE_CNAME:
        return "CNAME (canonical name for an alias)";
    case DNS_TYPE_SOA:
        return "SOA (start of a zone of authority)";
    case DNS_TYPE_PTR:
        return "PTR (domain name pointer)";
    case DNS_TYPE_MX:
        return "MX (mail exchange)";
    case DNS_TYPE_AAAA:
        return "AAAA (IPv6 host address)";
    case DNS_TYPE_HINFO:
        return "HINFO (host information)";
    case DNS_TYPE_TXT:
        return "TXT (text strings)";
    case DNS_TYPE_SRV:
        return "SRV (service location)";
    case DNS_TYPE_OPT:
        return "OPT (option pseudo record)";
    case DNS_TYPE_NSEC:
        return "NSEC (next secure record)";
    case DNS_QTYPE_AXFR:
        return "AXFR (zone transfer)";
    case DNS_QTYPE_STAR:
        return "* (all records)";
    default:
        return "";
    }
}

char *get_dns_class(uint16_t rrclass)
{
    switch (rrclass) {
    case DNS_CLASS_IN:
        return "IN";
    case DNS_CLASS_CS:
        return "CS";
    case DNS_CLASS_CH:
        return "CH";
    case DNS_CLASS_HS:
        return "HS";
    default:
        return "";
    }
}

char *get_dns_class_extended(uint16_t rrclass)
{
    switch (rrclass) {
    case DNS_CLASS_IN:
        return "IN (Internet)";
    case DNS_CLASS_CS:
        return "CS (CSNET class)";
    case DNS_CLASS_CH:
        return "CH (Chaos class)";
    case DNS_CLASS_HS:
        return "HS (Hesiod)";
    default:
        return "";
    }
}

int get_dns_max_namelen(struct dns_resource_record *record, int n)
{
    int maxlen = 0;

    for (int i = 0; i < n; i++) {
        int len = strlen(record[i].name);
        if (len > maxlen) {
            maxlen = len;
        }
    }
    return maxlen;
}

struct packet_flags *get_dns_flags()
{
    return dns_flags;
}

int get_dns_flags_size()
{
    return sizeof(dns_flags) / sizeof(struct packet_flags);
}

struct packet_flags *get_llmnr_flags()
{
    return llmnr_flags;
}

int get_llmnr_flags_size()
{
    return sizeof(llmnr_flags) / sizeof(struct packet_flags);
}
