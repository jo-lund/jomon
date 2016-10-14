#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packet_dns.h"
#include "packet.h"

#define DNS_PTR_LEN 2

static void parse_dns_record(int i, unsigned char *buffer, unsigned char **data, struct dns_info *dns);
static char *parse_dns_txt(unsigned char **data);

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
 * |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
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
bool handle_dns(unsigned char *buffer, struct application_info *info, uint16_t len)
{
    unsigned char *ptr = buffer;

    if (len < DNS_HDRLEN) return false;

    // TODO: Handle more than one question
    if ((ptr[4] << 8 | ptr[5]) > 0x1) { /* the QDCOUNT will in practice always be one */
        return false;
    }
    info->dns = malloc(sizeof(struct dns_info));
    info->dns->id = ptr[0] << 8 | ptr[1];
    info->dns->qr = (ptr[2] & 0x80) >> 7;
    info->dns->opcode = (ptr[2] & 0x78) >> 3;
    info->dns->aa = (ptr[2] & 0x04) >> 2;
    info->dns->tc = (ptr[2] & 0x02) >> 1;
    info->dns->rd = ptr[2] & 0x01;
    info->dns->ra = (ptr[3] & 0x80) >> 7;
    info->dns->rcode = ptr[3] & 0x0f;
    for (int i = 0, j = 4; i < 4; i++, j += 2) {
        info->dns->section_count[i] = ptr[j] << 8 | ptr[j + 1];
    }
    info->dns->record = NULL;

    if (info->dns->qr) { /* DNS response */
        ptr += DNS_HDRLEN;

        /* QUESTION section */
        if (info->dns->section_count[QDCOUNT] > 0) {
            ptr += parse_dns_name(buffer, ptr, info->dns->question.qname);
            info->dns->question.qtype = ptr[0] << 8 | ptr[1];
            info->dns->question.qclass = ptr[2] << 8 | ptr[3];
            ptr += 4; /* skip qtype and qclass */
        }

        /* Answer/Authority/Additional records sections */
        int num_records = 0;

        for (int i = ANCOUNT; i < 4; i++) {
            num_records += info->dns->section_count[i];
        }
        info->dns->record = malloc(num_records * sizeof(struct dns_resource_record));
        for (int i = 0; i < num_records; i++) {
            parse_dns_record(i, buffer, &ptr, info->dns);
        }
    } else { /* DNS query */
        if (info->dns->rcode != 0) { /* RCODE will be zero */
            free(info->dns);
            return false;
        }
        /* ANCOUNT and NSCOUNT values are zero */
        if (info->dns->section_count[ANCOUNT] != 0 && info->dns->section_count[NSCOUNT] != 0) {
            free(info->dns);
            return false;
        }
        /*
         * ARCOUNT will typically be 0, 1, or 2, depending on whether EDNS0
         * (RFC 2671) or TSIG (RFC 2845) are used
         */
        if (info->dns->section_count[ARCOUNT] > 2) {
            free(info->dns);
            return false;
        }
        ptr += DNS_HDRLEN;

        /* QUESTION section */
        if (info->dns->section_count[QDCOUNT] > 0) {
            ptr += parse_dns_name(buffer, ptr, info->dns->question.qname);
            info->dns->question.qtype = ptr[0] << 8 | ptr[1];
            info->dns->question.qclass = ptr[2] << 8 | ptr[3];
        }

        /* Additional records */
        if (info->dns->section_count[ARCOUNT]) {
            info->dns->record = malloc(info->dns->section_count[ARCOUNT] *
                                           sizeof(struct dns_resource_record));
            for (int i = 0; i < info->dns->section_count[ARCOUNT]; i++) {
                parse_dns_record(i, buffer, &ptr, info->dns);
            }
        }
    }
    return true;
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
int parse_dns_name(unsigned char *buffer, unsigned char *ptr, char name[])
{
    unsigned int n = 0; /* total length of name entry */
    unsigned int label_length = ptr[0];
    bool compression = false;
    unsigned int name_ptr_len = 0;

    if (!label_length) return 1; /* length octet */

    while (label_length) {
        /*
         * The max size of a label is 63 bytes, so a length with the first 2 bits
         * set to 11 indicates that the label is a pointer to a prior occurrence
         * of the same name. The pointer is an offset from the beginnng of the
         * DNS message, i.e. the ID field of the header.
         *
         * The pointer takes the form of a two octet sequence:
         *
         * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         * | 1  1|                OFFSET                   |
         * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         */
        if (label_length & 0xc0) {
            uint16_t offset = (ptr[0] & 0x3f) << 8 | ptr[1];

            label_length = buffer[offset];
            memcpy(name + n, buffer + offset + 1, label_length);
            ptr = buffer + offset; /* ptr will point to start of label */

            /*
             * Only update name_ptr_len if this is the first pointer encountered.
             * name_ptr_len must not include the ptrs in the prior occurrence of
             * the same name, i.e. if the name is a pointer to a sequence of
             * labeles ending in a pointer.
             */
            if (!compression) {
                /*
                 * Total length of the name entry encountered so far + ptr. If name
                 * is just a pointer, n will be 0
                 */
                name_ptr_len = n + DNS_PTR_LEN;
                compression = true;
            }
        } else {
            memcpy(name + n, ptr + 1, label_length);
        }
        n += label_length;
        name[n++] = '.';
        ptr += label_length + 1; /* skip length octet + rest of label */
        label_length = ptr[0];
    }
    name[n - 1] = '\0';
    n++; /* add null label */
    return compression ? name_ptr_len : n;
}

/*
 * Parse a DNS resource record.
 * int i is the recource record index.
 */
void parse_dns_record(int i, unsigned char *buffer, unsigned char **data, struct dns_info *dns)
{
    uint16_t rdlen;
    unsigned char *ptr = *data;

    ptr += parse_dns_name(buffer, ptr, dns->record[i].name);
    dns->record[i].type = ptr[0] << 8 | ptr[1];
    dns->record[i].rrclass = ptr[2] << 8 | ptr[3];
    dns->record[i].ttl = ptr[4] << 24 | ptr[5] << 16 | ptr[6] << 8 | ptr[7];
    rdlen = ptr[8] << 8 | ptr[9];
    ptr += 10; /* skip to rdata field */

    if (GET_MDNS_RRCLASS(dns->record[i].rrclass) == DNS_CLASS_IN) {
        switch (dns->record[i].type) {
        case DNS_TYPE_A:
            if (rdlen == 4) {
                dns->record[i].rdata.address = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            }
            ptr += rdlen;
            break;
        case DNS_TYPE_NS:
            ptr += parse_dns_name(buffer, ptr, dns->record[i].rdata.nsdname);
        case DNS_TYPE_CNAME:
            ptr += parse_dns_name(buffer, ptr, dns->record[i].rdata.cname);
            break;
        case DNS_TYPE_SOA:
            ptr += parse_dns_name(buffer, ptr, dns->record[i].rdata.soa.mname);
            ptr += parse_dns_name(buffer, ptr, dns->record[i].rdata.soa.rname);
            dns->record[i].rdata.soa.serial = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            ptr += 4;
            dns->record[i].rdata.soa.refresh = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            ptr += 4;
            dns->record[i].rdata.soa.retry = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            ptr += 4;
            dns->record[i].rdata.soa.expire = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            ptr += 4;
            dns->record[i].rdata.soa.minimum = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            ptr += 4;
            break;
        case DNS_TYPE_PTR:
            ptr += parse_dns_name(buffer, ptr, dns->record[i].rdata.ptrdname);
            break;
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
            int i = 0;

            dns->record[i].rdata.txt = list_init(NULL);
            while (i < rdlen) {
                char *txt;

                txt = parse_dns_txt(&ptr);
                list_push_back(dns->record[i].rdata.txt, txt);
                i += strlen(txt) + 1;
            }
            break;
        }
        default:
            ptr += rdlen;
            break;
        }
    } else {
        ptr += rdlen;
    }
    *data = ptr; /* skip parsed dns record */
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
    char *txt;
    uint8_t len;
    unsigned char *ptr = *data;

    len = *ptr;
    txt = malloc(len + 1);
    memcpy(txt, ++ptr, len);
    txt[len] = '\0';
    ptr += len;
    *data = ptr;
    return txt;
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
        return "HINFO (identifies the CPU and OS used by a host)";
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
