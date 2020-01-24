#ifndef PACKET_NBDS_H
#define PACKET_NBDS_H

#include <stdint.h>
#include <stdbool.h>
#include "packet_nbns.h"

/* message types */
#define NBDS_DIRECT_UNIQUE 0x10
#define NBDS_DIRECT_GROUP 0x11
#define NBDS_BROADCAST 0x12
#define NBDS_ERROR 0x13
#define NBDS_QUERY_REQUEST 0x14
#define NBDS_POSITIVE_QUERY_RESPONSE 0x15
#define NBDS_NEGATIVE_QUERY_RESPONSE 0x16

/* datagram error */
#define NBDS_DESTINATION_NAME_NOT_PRESENT 0x82
#define NBDS_INVALID_SOURCE_NAME 0x83
#define NBDS_INVALID_DESTINATION_NAME 0x84

/*
 * Bit definitions of the FLAGS field:
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 0 | 0 |  SNT  | F | M |
 * +---+---+---+---+---+---+---+---+
 */

/* MORE flag, if set then more NetBIOS datagram fragments follow.*/
#define GET_NBDS_MORE_FLAG(flags) ((flags) & 0x1)

/*
 * FIRST packet flag, if set then this is first (and possibly only) fragment of
 * NetBIOS datagram
 */
#define GET_NBDS_FIRST_FLAG(flags) ((flags) & 0x2)

/* Source End-node type  */
#define GET_NBDS_SNT_FLAG(flags) ((flags) & 0xc)

/* direct unique, direct group, and broadcast datagram */
struct nbds_datagram {
    uint16_t dgm_length; /* the number of bytes following the PACKET_OFFSET field */
    uint16_t packet_offset; /* Used in conjunction with the F and M flags in the header
                               to allow reconstruction of fragmented NetBIOS datagrams */
    char src_name[NBNS_NAMELEN];
    char dest_name[NBNS_NAMELEN];
};

struct nbds_info {
    uint8_t msg_type;
    uint8_t flags;
    uint16_t dgm_id;
    uint32_t source_ip;
    uint16_t source_port;
    union {
        struct nbds_datagram *dgm;
        uint8_t error_code; /* datagram error packet */

        /* datagram query request or positive or negative query response */
        char dest_name[NBNS_NAMELEN];
    } msg;
};

struct packet_flags *get_nbds_flags();
int get_nbds_flags_size();
char *get_nbds_message_type(uint8_t type);

/* internal to the decoder */
void register_nbds();
packet_error handle_nbds(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata);

#endif
