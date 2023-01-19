#ifndef PACKET_SNMP_H
#define PACKET_SNMP_H

#include <stdint.h>
#include <stdbool.h>
#include "../list.h"
#include "packet.h"

/* PDU types */
#define SNMP_GET_REQUEST 0
#define SNMP_GET_NEXT_REQUEST 1
#define SNMP_GET_RESPONSE 2
#define SNMP_SET_REQUEST 3
#define SNMP_TRAP 4

/* error status */
#define SNMP_NO_ERROR 0
#define SNMP_TOO_BIG 1      /* agent could not fit reply into a single SNMP message */
#define SNMP_NO_SUCH_NAME 2 /* operation specified a nonexistent variable */
#define SNMP_BAD_VALUE 3    /* a set operation specified an invalid value or syntax */
#define SNMP_READ_ONLY 4    /* manager tried to modify a read-only variable */
#define SNMP_GEN_ERR 5      /* some other error */

/* value types */
#define SNMP_BOOLEAN_TAG 1
#define SNMP_INTEGER_TAG 2
#define SNMP_BIT_STRING_TAG 3
#define SNMP_OCTET_STRING_TAG 4
#define SNMP_NULL_TAG 5
#define SNMP_OBJECT_ID_TAG 6
#define SNMP_SEQUENCE_TAG 16

/* trap types */
#define SNMP_COLD_START 0
#define SNMP_WARM_START 1
#define SNMP_LINK_DOWN 2
#define SNMP_LINK_UP 3
#define SNMP_AUTHENTICATION_FAILURE 4
#define SNMP_EGP_NEIGHBOR_LOSS 5
#define SNMP_ENTERPRISE_SPECIFIC 6


typedef char* oid;

struct snmp_varbind {
    oid object_name;
    uint8_t type;
    uint32_t plen;
    union {
        int32_t ival;
        char *pval;
    } object_syntax;
};

struct snmp_pdu {
    uint32_t request_id;
    uint32_t error_status;
    uint32_t error_index;
    list_t *varbind_list;
};

struct snmp_trap {
    oid enterprise;
    char *agent_addr;
    uint8_t trap_type;
    uint8_t specific_code;
    uint32_t timestamp; /* representing the number of hundreths of a second since
                           the agent initialized */
    list_t *varbind_list;
};

struct snmp_info {
    uint8_t version;
    char *community;
    uint8_t pdu_type;
    union {
        struct snmp_pdu *pdu;
        struct snmp_trap *trap;
    };
};

struct application_info;

char *get_snmp_type(struct snmp_info *snmp);
char *get_snmp_error_status(struct snmp_pdu *pdu);
char *get_snmp_trap_type(struct snmp_trap *pdu);

void register_snmp(void);


#endif
