#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include "packet_snmp.h"
#include "packet.h"

/*
 * there are at most 128 sub-indentifiers in a value and each sub-identifier has
 * a maximun value of 2^32 - 1
 */
#define MAX_OID_LEN 512

#define MIN_MSG 6 /* tag and length bytes */

/* class */
#define UNIVERSAL 0
#define APPLICATION 1
#define CONTEXT_SPECIFIC 2
#define PRIVATE 3

/* application types (defined in rfc 1155) */
#define IP_ADDRESS 0
#define COUNTER 1
#define GAUGE 2
#define TIMETICKS 3
#define OPAQUE 4

typedef union {
    uint32_t ival;
    char *pval;
} snmp_value;

static bool parse_pdu(unsigned char *buffer, int n, struct snmp_info *snmp);
static list_t *parse_variables(unsigned char *buffer, int n);
static uint32_t parse_value(unsigned char **data, uint8_t *class, uint8_t *tag,
                            snmp_value *value);
static void free_snmp_varbind(void *data);

/*
 * SNMP messages use a tag-length-value encding scheme (Basic Encoding Rules).
 * SNMP uses only a subset of the basic encoding rules of ASN.1. Namely, all
 * encodings use the definite-length form. Further, whenever permissible,
 * non-constructor encodings are used rather than constructor encodings.
 */
bool handle_snmp(unsigned char *buffer, int n, struct application_info *adu)
{
    uint8_t class;
    uint8_t tag;
    uint32_t msg_len;
    unsigned char *ptr = buffer;

    pstat[PROT_SNMP].num_packets++;
    pstat[PROT_SNMP].num_bytes += n;
    adu->snmp = calloc(1, sizeof(struct snmp_info));
    if (n > MIN_MSG) {
        msg_len = parse_value(&ptr, &class, &tag, NULL);
    }
    if (tag == SNMP_SEQUENCE_TAG) {
        return parse_pdu(ptr, msg_len, adu->snmp);
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
        /* common header */
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
                for (int i = 0; i < 3 && n > 0; i++) {
                    n -= parse_value(&ptr, &class, &tag, &val[i]);
                }
                if (n > 0) {
                    snmp->pdu = malloc(sizeof(struct snmp_pdu));
                    snmp->pdu->request_id = val[0].ival;
                    snmp->pdu->error_status = val[1].ival;
                    snmp->pdu->error_index = val[2].ival;
                    snmp->pdu->varbind_list = parse_variables(ptr, n);
                    return true;
                }
                return false;
            }
            case SNMP_TRAP:
            {
                uint8_t class;
                uint8_t tag;
                snmp_value val[5];

                for (int i = 0; i < 5 && n > 0; i++) {
                    n -= parse_value(&ptr, &class, &tag, &val[i]);
                }
                if (n > 0) {
                    snmp->trap = malloc(sizeof(struct snmp_trap));
                    snmp->trap->enterprise = val[0].pval;
                    snmp->trap->agent_addr = val[1].pval;
                    snmp->trap->trap_type = val[2].ival;
                    snmp->trap->specific_code = val[3].ival;
                    snmp->trap->timestamp = val[4].ival;
                    snmp->trap->varbind_list = parse_variables(ptr, n);
                    return true;
                }
                return false;
            }
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
list_t *parse_variables(unsigned char *buffer, int n)
{
    uint8_t class;
    uint8_t tag;
    unsigned char *ptr = buffer;
    list_t *varbind_list;

    varbind_list = list_init();
    n = parse_value(&ptr, &class, &tag, NULL);
    if (tag == SNMP_SEQUENCE_TAG) {
        while (n > 0) {
            snmp_value val;

            n -= parse_value(&ptr, &class, &tag, &val);
            if (tag == SNMP_SEQUENCE_TAG && n >= 0) {
                n -= parse_value(&ptr, &class, &tag, &val);
                if (tag == SNMP_OBJECT_ID_TAG && n > 0) {
                    struct snmp_varbind *var;

                    var = malloc(sizeof(struct snmp_varbind));
                    var->object_name = val.pval;
                    n -= parse_value(&ptr, &class, &tag, &val);
                    var->type = tag;
                    switch (tag) {
                    case SNMP_INTEGER_TAG:
                        var->object_syntax.ival = val.ival;
                        break;
                    case SNMP_OCTET_STRING_TAG:
                    case SNMP_OBJECT_ID_TAG:
                    case SNMP_NULL_TAG:
                        var->object_syntax.pval = val.pval;
                        break;
                    default:
                        break;
                    }
                    list_push_back(varbind_list, var);
                }
            }
        }
    }
    return varbind_list;
}

uint32_t parse_value(unsigned char **data, uint8_t *class, uint8_t *tag, snmp_value *value)
{
    uint32_t len = 0;
    unsigned char *ptr = *data;
    int len_num_octets = 0;

    /*
     * For low-tag-number form (tags 0 - 30), the first two bits specify the
     * class, and bit 6 indicates whether the encoding method is primitive or
     * constructed. The rest of the bits give the tag number.
     */
    *class = (*ptr & 0xc0) >> 6;
    *tag = *ptr & 0x1f;
    ptr++;
    if (*ptr & 0x80) { /* long form */
        len_num_octets = *ptr & 0x7f;
        if (len_num_octets <= 4) {
            for (int i = 0; i < len_num_octets; i++) {
                len = len << 8 | *++ptr;
            }
        }
    } else { /* short form */
        len = *ptr;
    }
    ptr++; /* skip (last) length byte */

    if (value && *class == APPLICATION) { /* application specific */
        switch (*tag) {
        case IP_ADDRESS:
        {
            int j = 0;

            value->pval = malloc(INET_ADDRSTRLEN);
            for (int i = 0; i < len; i++) {
                j += snprintf(value->pval + j, INET_ADDRSTRLEN - j, "%d.", *ptr++);
            }
            if (j < INET_ADDRSTRLEN) {
                value->pval[j-1] = '\0';
            }
            break;
        }
        case OPAQUE:
            *tag = SNMP_OCTET_STRING_TAG;
            break;
        case COUNTER:
        case GAUGE:
        case TIMETICKS:
            *tag = SNMP_INTEGER_TAG;
            break;
        default:
            break;
        }
    }

    if (value && (*class == UNIVERSAL || *class == APPLICATION)) {
        switch (*tag) {
        case SNMP_INTEGER_TAG:
            value->ival = 0;
            for (int i = 0; i < len; i++) {
                value->ival = value->ival << 8 | *ptr++;
            }
            /* add tag and length bytes */
            len = (len_num_octets) ? len + len_num_octets : len + 2;
            break;
        case SNMP_OCTET_STRING_TAG:
            if (len > 0) {
                value->pval = malloc(len);
                memcpy(value->pval, ptr, len);
                ptr += len;
            }
            /* add tag and length bytes */
            len = (len_num_octets) ? len + len_num_octets : len + 2;
            break;
        case SNMP_OBJECT_ID_TAG:
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
                ptr += len;

                /* add tag and length bytes */
                len = (len_num_octets) ? len + len_num_octets : len + 2;
            }
            break;
        case SNMP_NULL_TAG:
            value->pval = NULL;
            len = 2; /* tag and length bytes */
            break;
        case SNMP_SEQUENCE_TAG:
            /* only add tag and length bytes */
            len = (len_num_octets) ? len_num_octets : 2;
            break;
        default:
            break;
        }
    }
    *data = ptr;
    return len;
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

void free_snmp_varbind(void *data)
{
    struct snmp_varbind *var = (struct snmp_varbind *) data;

    if (var->type == SNMP_OCTET_STRING_TAG || var->type == SNMP_OBJECT_ID_TAG) {
        if (var->object_syntax.pval) {
            free(var->object_syntax.pval);
        }
    }
    free(var);
}

void free_snmp_packet(struct snmp_info *snmp)
{
    if (snmp->community) {
        free(snmp->community);
    }
    switch (snmp->pdu_type) {
    case SNMP_GET_REQUEST:
    case SNMP_GET_NEXT_REQUEST:
    case SNMP_SET_REQUEST:
    case SNMP_GET_RESPONSE:
        list_free(snmp->pdu->varbind_list, free_snmp_varbind);
        free(snmp->pdu);
        break;
    case SNMP_TRAP:
        free(snmp->trap->enterprise);
        free(snmp->trap->agent_addr);
        list_free(snmp->trap->varbind_list, free_snmp_varbind);
        free(snmp->trap);
        break;
    default:
        break;
    }
    free(snmp);
}
