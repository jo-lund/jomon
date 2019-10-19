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

#define MIN_MSG 18 /* should at least contain a minimum header */

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

typedef struct {
    uint32_t plen;
    union {
        uint32_t ival;
        char *pval;
    };
} snmp_value;

extern void print_snmp(char *buf, int n, void *data);
extern void add_snmp_information(void *widget, void *subwidget, void *data);
static packet_error parse_pdu(unsigned char *buffer, int n, struct snmp_info *snmp);
static list_t *parse_variables(unsigned char *buffer, int n);
static int parse_value(unsigned char **data, int n, uint8_t *class, uint8_t *tag,
                       snmp_value *value);

static struct protocol_info snmp_prot = {
    .short_name = "SNMP",
    .long_name = "Simple Network Management Protocol",
    .port = SNMP,
    .decode = handle_snmp,
    .print_pdu = print_snmp,
    .add_pdu = add_snmp_information
};

static struct protocol_info snmptrap_prot = {
    .short_name = "SNMP",
    .long_name = "Simple Network Management Protocol",
    .port = SNMPTRAP,
    .decode = handle_snmp,
    .print_pdu = print_snmp,
    .add_pdu = add_snmp_information
};

void register_snmp()
{
    register_protocol(&snmp_prot, LAYER4);
    register_protocol(&snmptrap_prot, LAYER4);
}

/*
 * SNMP messages use a tag-length-value encoding scheme (Basic Encoding Rules).
 * SNMP uses only a subset of the basic encoding rules of ASN.1. Namely, all
 * encodings use the definite-length form. Further, whenever permissible,
 * non-constructor encodings are used rather than constructor encodings.
 */
packet_error handle_snmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         void *data)
{
    uint8_t class;
    uint8_t tag;
    int msg_len;
    unsigned char *ptr = buffer;
    struct application_info *adu = data;

    if (n < MIN_MSG) return SNMP_ERR;

    adu->snmp = mempool_pealloc(sizeof(struct snmp_info));
    if ((msg_len = parse_value(&ptr, n, &class, &tag, NULL)) == -1) {
        return SNMP_ERR;
    }
    if (tag == SNMP_SEQUENCE_TAG) {
        pinfo->num_packets++;
        pinfo->num_bytes += n;
        return parse_pdu(ptr, msg_len, adu->snmp);
    }
    return SNMP_ERR;
}

/*
 * The common SNMP header contains a sequence consisting of:
 * version - integer (version number - 1)
 * community - octet string
 * PDU type - context specific with tag from 0 - 4
 */
packet_error parse_pdu(unsigned char *buffer, int n, struct snmp_info *snmp)
{
    uint8_t class;
    uint8_t tag;
    unsigned char *ptr = buffer;
    snmp_value val[2];
    int val_len;

    for (int i = 0; i < 2 && n > 0; i++) {
        if ((val_len = parse_value(&ptr, n, &class, &tag, &val[i])) == -1) {
            return SNMP_ERR;
        }
        n -= val_len;
    }
    if (n > 0) {
        /* common header */
        snmp->version = val[0].ival;
        snmp->community = val[1].pval;

        /* get PDU type */
        if ((n = parse_value(&ptr, n, &class, &tag, NULL)) == -1) {
            return SNMP_ERR;
        }
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
                    if ((val_len = parse_value(&ptr, n, &class, &tag, &val[i])) == -1) {
                        return SNMP_ERR;
                    }
                    n -= val_len;
                }
                if (n > 0) {
                    snmp->pdu = mempool_pealloc(sizeof(struct snmp_pdu));
                    snmp->pdu->request_id = val[0].ival;
                    snmp->pdu->error_status = val[1].ival;
                    snmp->pdu->error_index = val[2].ival;
                    if ((snmp->pdu->varbind_list = parse_variables(ptr, n)) == NULL) {
                        return SNMP_ERR;
                    }
                    return NO_ERR;
                }
                return SNMP_ERR;
            }
            case SNMP_TRAP:
            {
                uint8_t class;
                uint8_t tag;
                snmp_value val[5];

                for (int i = 0; i < 5 && n > 0; i++) {
                    if ((val_len = parse_value(&ptr, n, &class, &tag, &val[i])) == -1) {
                        return SNMP_ERR;
                    }
                    n -= val_len;
                }
                if (n > 0) {
                    snmp->trap = mempool_pealloc(sizeof(struct snmp_trap));
                    snmp->trap->enterprise = val[0].pval;
                    snmp->trap->agent_addr = val[1].pval;
                    snmp->trap->trap_type = val[2].ival;
                    snmp->trap->specific_code = val[3].ival;
                    snmp->trap->timestamp = val[4].ival;
                    if ((snmp->trap->varbind_list = parse_variables(ptr, n)) == NULL) {
                        return SNMP_ERR;
                    }
                    return NO_ERR;
                }
                return SNMP_ERR;
            }
            default:
                return SNMP_ERR;
            }
        }
    }
    return SNMP_ERR;
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

    varbind_list = list_init(&d_alloc);
    if ((n = parse_value(&ptr, n, &class, &tag, NULL)) == -1) {
        return NULL;
    }
    if (tag == SNMP_SEQUENCE_TAG) {
        while (n > 0) {
            snmp_value val;
            int val_len;

            if ((val_len = parse_value(&ptr, n, &class, &tag, &val)) == -1) {
                return NULL;
            }
            n -= val_len;
            if (tag == SNMP_SEQUENCE_TAG && n > 0) {
                if ((val_len = parse_value(&ptr, n, &class, &tag, &val)) == -1) {
                    return NULL;
                }
                n -= val_len;
                if (tag == SNMP_OBJECT_ID_TAG && n > 0) {
                    struct snmp_varbind *var;

                    var = mempool_pealloc(sizeof(struct snmp_varbind));
                    var->object_name = val.pval;
                    if ((val_len = parse_value(&ptr, n, &class, &tag, &val)) == -1) {
                        return NULL;
                    }
                    n -= val_len;
                    var->type = tag;
                    switch (tag) {
                    case SNMP_INTEGER_TAG:
                        var->object_syntax.ival = val.ival;
                        break;
                    case SNMP_OCTET_STRING_TAG:
                    case SNMP_OBJECT_ID_TAG:
                    case SNMP_NULL_TAG:
                        var->object_syntax.pval = val.pval;
                        var->plen = val.plen;
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

int parse_value(unsigned char **data, int n, uint8_t *class, uint8_t *tag, snmp_value *value)
{
    unsigned int len = 0;
    unsigned char *ptr = *data;
    unsigned int len_num_octets = 0;

    /*
     * For low-tag-number form (tags 0 - 30), the first two bits specify the
     * class, and bit 6 indicates whether the encoding method is primitive or
     * constructed. The rest of the bits give the tag number.
     */
    *class = (*ptr & 0xc0) >> 6;
    *tag = *ptr & 0x1f;
    ptr++;
    if (*ptr & 0x80) { /* long form - for lengths between 0 and 2^1008 - 1 */
        len_num_octets = *ptr & 0x7f;
        if (len_num_octets <= 4) { /* ignore length greater than 2^32 */
            for (unsigned int i = 0; i < len_num_octets; i++) {
                len = len << 8 | *++ptr;
            }
        } else {
            return -1;
        }
    } else { /* short form */
        len = *ptr;
    }
    if (len > (unsigned int) n) {
        return -1;
    }
    ptr++; /* skip (last) length byte */

    if (value && *class == APPLICATION) { /* application specific */
        switch (*tag) {
        case IP_ADDRESS:
        {
            int j = 0;

            value->pval = mempool_pealloc(INET_ADDRSTRLEN);
            for (unsigned int i = 0; i < len; i++) {
                j += snprintf(value->pval + j, INET_ADDRSTRLEN - j, "%d.", *ptr++);
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
            for (unsigned int i = 0; i < len; i++) {
                value->ival = value->ival << 8 | *ptr++;
            }
            /* add tag and length bytes */
            len += len_num_octets + 2;
            break;
        case SNMP_OCTET_STRING_TAG:
            if (len > 0) {
                value->pval = mempool_pealloc(len + 1);
                memcpy(value->pval, ptr, len);
                value->pval[len] = '\0';
                value->plen = len;
                ptr += len;
            } else {
                value->pval = NULL;
                value->plen = 0;
            }
            /* add tag and length bytes */
            len += len_num_octets + 2;
            break;
        case SNMP_OBJECT_ID_TAG:
            if (len > 0) {
                char val[MAX_OID_LEN];
                unsigned int i = 0;
                unsigned int j = 0;
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
                value->pval = mempool_pealloc(strlen(val) + 1);
                strcpy(value->pval, val);
                value->plen = len;
                ptr += len;
            } else {
                value->pval = NULL;
                value->plen = 0;
            }
            /* add tag and length bytes */
            len += len_num_octets + 2;
            break;
        case SNMP_NULL_TAG:
            value->pval = NULL;
            value->plen = 0;
            len = 2; /* tag and length bytes */
            break;
        case SNMP_SEQUENCE_TAG:
            /* only tag and length bytes */
            len = len_num_octets + 2;
            break;
        default:
            len += len_num_octets + 2;
            break;
        }
    } else if (*class == CONTEXT_SPECIFIC) {
        len += len_num_octets + 2;
    }
    *data = ptr;
    if (len == 0) {
        return len_num_octets + 2;
    }
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

char *get_snmp_error_status(struct snmp_pdu *pdu)
{
    switch (pdu->error_status) {
    case SNMP_NO_ERROR:
        return "noError";
    case SNMP_TOO_BIG:
        return "tooBig";
    case SNMP_NO_SUCH_NAME:
        return "noSuchName";
    case SNMP_BAD_VALUE:
        return "badValue";
    case SNMP_READ_ONLY:
        return "readOnly";
    case SNMP_GEN_ERR:
        return "genError";
    default:
        return NULL;
    }
}

char *get_snmp_trap_type(struct snmp_trap *pdu)
{
    switch (pdu->trap_type) {
    case SNMP_COLD_START:
        return "coldStart";
    case SNMP_WARM_START:
        return "warmStart";
    case SNMP_LINK_DOWN:
        return "LinkDown";
    case SNMP_LINK_UP:
        return "LinkUp";
    case SNMP_AUTHENTICATION_FAILURE:
        return "authenticationFailure";
    case SNMP_EGP_NEIGHBOR_LOSS:
        return "egpNeighborLoss";
    case SNMP_ENTERPRISE_SPECIFIC:
        return "enterpriseSpecific";
    default:
        return NULL;
    }
}
