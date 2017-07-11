#include <string.h>
#include <stdio.h>
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

typedef union {
    uint32_t ival;
    char *pval;
} snmp_value;

static bool parse_message(unsigned char *buffer, int n, struct snmp_info *snmp);
static bool parse_pdu(unsigned char *buffer, int n, struct snmp_info *snmp);
static bool parse_variables(unsigned char *buffer, int n, struct snmp_pdu *pdu);
static uint32_t parse_value(unsigned char **data, uint8_t *class, uint8_t *tag,
                            snmp_value *value);
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
        return parse_pdu(ptr, msg_len, snmp);
    }
    return false;
}

/*
 * The common SNMP header contains a sequence consisting of:
 * version - integer (version number - 1)
 * community - octet string
 * PDU type - context specific with tag from 0 - 4
 */
bool parse_pdu(unsigned char *buffer, int n, struct snmp_info *snmp)
{
    uint8_t class;
    uint8_t tag;
    unsigned char *ptr = buffer;
    snmp_value val[2];

    for (int i = 0; i < 2 && n > 0; i++) {
        n -= parse_value(&ptr, &class, &tag, &val[i]);
    }
    if (n > 0) {
        /* parse common header */
        snmp->version = val[0].ival;
        snmp->community = val[1].pval;
        n = parse_value(&ptr, &class, &tag, NULL); /* get PDU type */
        if (n > 0 && class == CONTEXT_SPECIFIC) {
            snmp->pdu_type = tag;
            switch (snmp->pdu_type) {
            case SNMP_GET_REQUEST:
            case SNMP_GET_NEXT_REQUEST:
            case SNMP_SET_REQUEST:
            case SNMP_GET_RESPONSE:
            {
                uint8_t class;
                uint8_t tag;
                snmp_value val[3];

                /* parse get/set header */
                snmp->pdu = malloc(sizeof(struct snmp_pdu));
                for (int i = 0; i < 3 && n > 0; i++) {
                    n -= parse_value(&ptr, &class, &tag, &val[i]);
                }
                if (n > 0) {
                    snmp->pdu->request_id = val[0].ival;
                    snmp->pdu->error_status = val[1].ival;
                    snmp->pdu->error_index = val[2].ival;
                    return parse_variables(ptr, n, snmp->pdu);
                }
                return false;
            }
            case SNMP_TRAP:
            default:
                return false;
            }
        }
    }
    return false;
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

    pdu->varbind_list = list_init();
    n = parse_value(&ptr, &class, &tag, NULL);
    if (tag == SEQUENCE_TAG) {
        while (n > 0) {
            n -= parse_value(&ptr, &class, &tag, NULL);
            if (tag == SEQUENCE_TAG && n > 0) {
                snmp_value val;

                n = parse_value(&ptr, &class, &tag, &val);
                if (tag == OBJECT_ID_TAG && n > 0) {
                    struct snmp_varbind *var;

                    var = malloc(sizeof(struct snmp_varbind));
                    var->object_name = val.pval;
                    n -= parse_value(&ptr, &class, &tag, &val);
                    var->type = tag;
                    switch (tag) {
                    case INTEGER_TAG:
                        var->object_syntax.ival = val.ival;
                        break;
                    case OCTET_STRING_TAG:
                    case OBJECT_ID_TAG:
                        var->object_syntax.pval = val.pval;
                        break;
                    case NULL_TAG:
                        var->object_syntax.pval = NULL;
                        break;
                    default:
                        break;
                    }
                    list_push_back(pdu->varbind_list, var);
                }
            }
        }
    }
    return true;
}

uint32_t parse_value(unsigned char **data, uint8_t *class, uint8_t *tag, snmp_value *value)
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
        if (num_octets <= 4) {
            for (int i = 0; i < num_octets; i++) {
                len = len << 8 | *++ptr;
            }
        }
    } else { /* short form */
        len = *ptr;
    }
    ptr++; /* skip (last) length byte */

    if (value && *class == 0) { /* universal */
        switch (*tag) {
        case INTEGER_TAG:
            value->ival = 0;
            for (int i = 0; i < len; i++) {
                value->ival = value->ival << 8 | *ptr++;
            }
            break;
        case OCTET_STRING_TAG:
            if (len > 0) {
                value->pval = malloc(len);
                memcpy(value->pval, ptr, len);
                ptr += len;
            }
            break;
        case OBJECT_ID_TAG:
            if (len > 0) {
                char val[MAX_OID_LEN];
                int i = 0;
                int j = 0;
                char c;

                /*
                 * The first two oid components are encoded as x * 40 + y, where
                 * x is the value of the first oid component and y the second.
                 */
                c = ptr[j++];
                val[0] = c / 40 + '0';
                val[1] = '.';
                i += 2;
                c %= 40;
                i += snprintf(val + i, MAX_OID_LEN - i, "%d.", c);
                while (i < MAX_OID_LEN && j < len) {
                    if (ptr[j] & 0x80) {
                        uint32_t v = 0;

                        for (int k = 0; k < 4 && ptr[j] & 0x80; k++) {
                            v = v << 7 | (ptr[j++] & 0x7f);
                        }
                        v = v << 7 | (ptr[j++] & 0x7f); /* last group */
                        i += snprintf(val + i, MAX_OID_LEN - i, "%d.", v);
                    } else {
                        uint8_t v;

                        v = ptr[j++];
                        i += snprintf(val + i, MAX_OID_LEN - i, "%d.", v);
                    }
                }
                val[i-1] = '\0';
                value->pval = malloc(strlen(val) + 1);
                strcpy(value->pval, val);
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
