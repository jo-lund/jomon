#ifndef PACKET_NBNS_H
#define PACKET_NBNS_H

#include <stdbool.h>
#include <stdint.h>
#include "packet.h"

#define NBNS_NAME_MAP_LEN 32
/*
 * NBNS names are represented by a name and suffix. Names are limited to 15 bytes
 * and the 16th byte is a NetBIOS suffix. Names are stored in a "name<suffix>"
 * format. Hex digits in the name are stored as <xx>.
 */
#define NBNS_NAMELEN (16 * 4 + 1)
#define MAX_NBNS_NAMES 8
#define MAX_NBNS_ADDR 8

/* NBNS opcodes */
#define NBNS_QUERY 0
#define NBNS_REGISTRATION 5
#define NBNS_RELEASE 6
#define NBNS_WACK 7
#define NBNS_REFRESH 8

/* NBNS response codes */
#define NBNS_NO_ERROR 0
#define NBNS_FMT_ERR 0x1 /* Format Error. Request was invalidly formatted */
#define NBNS_SRV_ERR 0x2 /* Server failure. Problem with NBNS, cannot process name */
#define NBNS_IMP_ERR 0x4 /* Unsupported request error. Allowable only for challenging
                            NBNS when gets an Update type registration request */
#define NBNS_RFS_ERR 0x5 /* Refused error. For policy reasons server will not
                            register this name from this host */
#define NBNS_ACT_ERR 0x6 /* Active error. Name is owned by another node */
#define NBNS_CFT_ERR 0x7 /* Name in conflict error. A UNIQUE name is owned by more
                            than one node */

/* NBNS types */
#define NBNS_A 0X0001    /* IP address Resource Record */
#define NBNS_NS 0x0002   /* Name Server Resource Record */
#define NBNS_NULL 0x000A /* NULL Resource Record */
#define NBNS_NB 0x0020   /* NetBIOS general Name Service Resource Record */
#define NBNS_NBSTAT 0x0021 /* NetBIOS NODE STATUS Resource Record */

/* NBNS class */
#define NBNS_IN 0x0001 /* Internet class */

/* NBNS owner node type */
#define NBNS_BNODE 0
#define NBNS_PNODE 1
#define NBNS_MNODE 2

struct nbns_info {
    uint16_t length; /* used by messages sent over TCP */
    uint16_t id;     /* transaction ID */
    unsigned int r      : 1; /* 0 request, 1 response */
    unsigned int opcode : 4; /* packet type code */
    unsigned int aa     : 1; /* authoritative answer */
    unsigned int tc     : 1; /* truncation */
    unsigned int rd     : 1; /* recursion desired */
    unsigned int ra     : 1; /* recursion avilable */
    unsigned int broadcast : 1; /* 1 broadcast or multicast, 0 unicast */
    unsigned int rcode  : 4;
    unsigned int section_count[4];

    /* question section */
    struct {
        /* the compressed name representation of the NetBIOS name for the request */
        char qname[NBNS_NAMELEN];
        uint16_t qtype;  /* the type of request */
        uint16_t qclass; /* the class of the request */
    } question;

    /* answer/additional records section */
    struct nbns_rr {
        /* the compressed name representation of the NetBIOS name corresponding
           to this resource record */
        char rrname[NBNS_NAMELEN];
        uint16_t rrtype; /* resource record type code */
        uint16_t rrclass; /* resource record class code */
        uint32_t ttl; /* the Time To Live of the resource record's name */

        /* rrtype and rrclass dependent field */
        union {
            struct {
                /*
                 * group name flag.
                 * 1 rrname is a group NetBIOS name
                 * 0 rrname is a unique NetBIOS name
                 */
                unsigned int g : 1;
                /*
                 * Owner Node Type:
                 *    00 = B node
                 *    01 = P node
                 *    10 = M node
                 *    11 = Reserved for future use
                 * For registration requests this is the claimant's type.
                 * For responses this is the actual owner's type.
                 */
                unsigned int ont : 2;
                uint8_t num_addr;
                uint32_t address[MAX_NBNS_ADDR]; /* IP address[es] of the name's owner */
            } nb;
            struct {
                char node_name[NBNS_NAMELEN];
                uint16_t name_flags;
            } nbstat[MAX_NBNS_NAMES];
            char nsdname[NBNS_NAMELEN];
            uint32_t nsdipaddr;
        } rdata;
    } *record;
};

char *get_nbns_opcode(uint8_t opcode);
char *get_nbns_rcode(uint8_t rcode);
char *get_nbns_type(uint16_t qtype);
char *get_nbns_type_extended(uint16_t qtype);
char *get_nbns_node_type(uint8_t type);
struct packet_flags *get_nbns_flags(void);
int get_nbns_flags_size(void);
struct packet_flags *get_nbns_nb_flags(void);
int get_nbns_nb_flags_size(void);

/*
 * Return the NetBIOS suffix definition. Assumes 'name' is a NetBIOS name stored
 * in "name<suffix>" format.
 */
char *get_nbns_suffix(char *name);

/* internal to the decoder */
void register_nbns(void);
packet_error handle_nbns(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata);
void decode_nbns_name(char *dest, char *src);

#endif
