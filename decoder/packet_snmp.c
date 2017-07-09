#include <string.h>
#include "packet_snmp.h"
#include "packet.h"
#include "../vector.h"

/*
 * there are at most 128 sub-indentifiers in a value and each sub-identifier has
 * a maximun value of 2^32 - 1
 */
#define MAX_OID_LEN 512

/* type */
#define BOOLEAN_TAG 1
#define INTEGER_TAG 2
#define BIT_STRING_TAG 3
#define OCTET_STRING_TAG 4
#define NULL_TAG 5
#define OBJECT_ID_TAG 6
#define SEQUENCE_TAG 16

/* class */
#define UNIVERSAL 0
#define APPLICATION 1
#define CONTEXT_SPECIFIC 2
#define PRIVATE 3

static bool parse_message(unsigned char *buffer, int n, struct snmp_info *snmp);
static bool parse_header(unsigned char *buffer, int n, struct snmp_info *snmp);
static bool parse_pdu(unsigned char *buffer, int n, struct snmp_info *snmp);
static bool parse_variables(unsigned char *buffer, int n, struct snmp_pdu *pdu);
static uint32_t parse_value(unsigned char **data, uint8_t *class, uint8_t *tag,
                            vector_t *vec);
/*
 * SNMP messages use a tag-length-value encding scheme (Basic Encoding Rules).
 * SNMP uses only a subset of the basic encoding rules of ASN.1. Namely, all
 * encodings use the definite-length form. Further, whenever permissible,
 * non-constructor encodings are used rather than constructor encodings.
 */
bool handle_snmp(unsigned char *buffer, int n, struct application_info *adu)
{
    bool error;

    adu->snmp = malloc(sizeof(struct snmp_info));
    error = parse_message(buffer, n, adu->snmp);
    pstat[PROT_SNMP].num_packets++;
    pstat[PROT_SNMP].num_bytes += n;
    return error;
}

bool parse_message(unsigned char *buffer, int n, struct snmp_info *snmp)
{
    uint8_t class;
    uint8_t tag;
    uint32_t msg_len;
    unsigned char *ptr = buffer;

    if (n > 2) { /* tag + length (short form) */
        msg_len = parse_value(&ptr, &class, &tag, NULL);
    }
    if (tag == SEQUENCE_TAG) {
        return parse_header(ptr, msg_len, snmp);
    }
    return false;
}

/*
 * The common SNMP header contains a sequence consisting of:
 * version - integer (version number - 1)
 * community - octet string
 * PDU type - context specific with tag from 0 - 4
 */
bool parse_header(unsigned char *buffer, int n, struct snmp_info *snmp)
{
    uint8_t class;
    uint8_t tag;
    unsigned char *ptr = buffer;
    vector_t *header;
    int i = 0;

    header = vector_init(2);
    while (n > 0 && i < 2) {
        n -= parse_value(&ptr, &class, &tag, header);
        i++;
    }
    if (n > 0 && i == 2) {
        snmp->version = * (uint8_t *) vector_get_data(header, 0);
        snmp->community = (char *) vector_get_data(header, 1);
        vector_pop_back(header, NULL); /* don't deallocate community ptr */
        vector_free(header, free);
    } else {
        return false;
    }

    /* get PDU type */
    n -= parse_value(&ptr, &class, &tag, NULL);
    if (n > 0 && class == CONTEXT_SPECIFIC) { /* class should be context specific */
        snmp->pdu_type = tag;
        return parse_pdu(ptr, n, snmp);
    }
    return false;
}

bool parse_pdu(unsigned char *buffer, int n, struct snmp_info *snmp)
{
    unsigned char *ptr = buffer;

    switch (snmp->pdu_type) {
    case SNMP_GET_REQUEST:
    case SNMP_GET_NEXT_REQUEST:
    case SNMP_SET_REQUEST:
    case SNMP_GET_RESPONSE:
    {
        uint8_t class;
        uint8_t tag;
        vector_t *pdu;
        int i = 0;

        /* parse get/set header */
        pdu = vector_init(3);
        snmp->pdu = malloc(sizeof(struct snmp_pdu));
        while (n > 0 && i < 3) {
            n -= parse_value(&ptr, &class, &tag, pdu);
            i++;
        }
        if (n > 0 && i == 3) {
            snmp->pdu->request_id = * (uint32_t *) vector_get_data(pdu, 0);
            snmp->pdu->error_status = * (uint32_t *) vector_get_data(pdu, 1);
            snmp->pdu->error_index = * (uint32_t *) vector_get_data(pdu, 2);
            vector_free(pdu, free);
            return parse_variables(ptr, n, snmp->pdu);
        }
        break;
    }
    case SNMP_TRAP:
    default:
        return false;
    }
}

/*
 * The variables start with a sequence consisting of object identifiers and
 * values (INTEGER, OCTET STRING, etc.)
 */
bool parse_variables(unsigned char *buffer, int n, struct snmp_pdu *pdu)
{
    uint8_t class;
    uint8_t tag;
    unsigned char *ptr = buffer;

    n -= parse_value(&ptr, &class, &tag, NULL);
    if (tag == SEQUENCE_TAG && n > 0) {
        parse_value(&ptr, &class, &tag, NULL);
    }
    return true;
}

uint32_t parse_value(unsigned char **data, uint8_t *class, uint8_t *tag, vector_t *vec)
{
    uint32_t len = 0;
    unsigned char *ptr = *data;

    /*
     * For low-tag-number form (tags 0 - 30), the first two bits specify the
     * class, and bit 6 indicates whether the encoding method is primitive or
     * constructed. The rest of the bits give the tag number.
     */
    *class = (*ptr & 0xc0) >> 6;
    *tag = *ptr & 0x1f;
    ptr++;
    if (*ptr & 0x80) { /* long form */
        int num_octets;

        num_octets = *ptr & 0x7f;
        if (num_octets <= 4) { /* BER has support for up to 127 octets */
            for (int i = 0; i < num_octets; i++) {
                len = len << 8 | *++ptr;
            }
        }
    } else { /* short form */
        len = *ptr;
    }
    ptr++; /* skip (last) length byte */

    if (vec && *class == 0) { /* universal */
        switch (*tag) {
        case INTEGER_TAG:
        {
            int32_t val = 0;
            int32_t *pval;

            for (int i = 0; i < len; i++) {
                val = val << 8 | *ptr++;
            }
            pval = malloc(sizeof(int32_t));
            *pval = val;
            vector_push_back(vec, pval);
            break;
        }
        case OCTET_STRING_TAG:
            if (len > 0) {
                char *pval;

                pval = malloc(len);
                memcpy(pval, ptr, len);
                vector_push_back(vec, pval);
                ptr += len;
            }
            break;
        case OBJECT_ID_TAG:
            if (len > 0) {
            }

            break;
        default:
            break;
        }
    }
    *data = ptr;
    return len + 2; /* tag and length bytes + length of content */
}

char *get_snmp_type(struct snmp_info *snmp)
{
    switch (snmp->pdu_type) {
    case SNMP_GET_REQUEST:
        return "GetRequest";
    case SNMP_GET_NEXT_REQUEST:
        return "GetNextRequest";
    case SNMP_SET_REQUEST:
        return "SetRequest";
    case SNMP_GET_RESPONSE:
        return "GetResponse";
    case SNMP_TRAP:
        return "Trap";
    default:
        return NULL;
    }
}
