#ifndef PACKET_SNMP_H
#define PACKET_SNMP_H

#include <stdint.h>
#include <stdbool.h>

/* PDU types */
#define SNMP_GET_REQUEST 0
#define SNMP_GET_NEXT_REQUEST 1
#define SNMP_SET_REQUEST 2
#define SNMP_GET_RESPONSE 3
#define SNMP_TRAP 4

/* error status */
#define SNMP_NO_ERROR 0
#define SNMP_TOO_BIG 1      /* agent could not fit reply into a single SNMP message */
#define SNMP_NO_SUCH_NAME 2 /* operation specified a nonexistent variable */
#define SNMP_BAD_VALUE 3    /* a set operation specified an invalid value or syntax */
#define SNMP_READ_ONLY 4    /* manager tried to modify a read-only variable */
#define SNMP_GEN_ERR        /* some other error */

typedef char* oid;

struct application_info;

struct snmp_pdu {
    uint32_t request_id;
    uint32_t error_status;
    uint32_t error_index;
    char data[];
};

struct snmp_trap {
    oid enterprise;
    uint32_t agent_addr;
    uint8_t trap_type;
    uint8_t specific_code;
    uint32_t timestamp; /* representing the number of hundreths of a second since
                           the agent initialized */
    char data[];
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

char *get_snmp_type(struct snmp_info *snmp);
bool handle_snmp(unsigned char *buffer, int n, struct application_info *adu);

#endif
