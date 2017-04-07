#ifndef PACKET_PIM_H
#define PACKET_PIM_H

#include "../list.h"
#include <stdbool.h>
#include <stdint.h>

/* message types */
#define PIM_HELLO 0
#define PIM_REGISTER 1       /* used in PIM-SM only */
#define PIM_REGISTER_STOP 2  /* used in PIM-SM only */
#define PIM_JOIN_PRUNE 3
#define PIM_BOOTSTRAP 4 /* used in PIM-SM only */
#define PIM_ASSERT 5
#define PIM_GRAFT 6     /* used in PIM-DM only */
#define PIM_GRAFT_ACK 7 /* used in PIM-DM only */
#define PIM_CANDIDATE_RP_ADVERTISEMENT 8
#define PIM_STATE_REFRESH 9

/* Hello message options */
#define PIM_HOLDTIME 1
#define PIM_LAN_PRUNE_DELAY 2
#define PIM_DR_PRIORITY 19
#define PIM_GENERATION_ID 20
#define PIM_STATE_REFRESH_CAPABLE 21
#define PIM_ADDRESS_LIST 24

// TODO: Move this
/* Address Family numbers, cf. www.iana.org */
#define AF_IP 1
#define AF_IP6 2
#define AF_802 6

#define GET_RPTBIT(mp) ((mp) >> 31)
#define GET_METRIC_PREFERENCE(mp) ((mp) & 0x7fffffff)

struct pim_unicast_addr {
    uint8_t addr_family;
    uint8_t encoding;
    unsigned char *addr; /* Unicast address as represented by the given address
                            family and encoding type */
};

struct pim_group_addr {
    uint8_t addr_family;
    uint8_t encoding;
    unsigned int bidirectional : 1;
    unsigned int zone : 1;
    uint8_t mask_len;
    unsigned char *addr; /* contains the group multicast address */
};

struct pim_source_addr {
    uint8_t addr_family;
    uint8_t encoding;
    unsigned int sparse : 1; /* the sparse bit is set to 1 for PIM-SM */
    unsigned int wc : 1; /* the wildcard bit is for use with Join/Prune messages */
    unsigned int rpt : 1; /* the rendezvous point tree bit is for use with
                           Join/Prune messages */
    uint8_t mask_len;
    unsigned char *addr; /* the source address */
};

/* this is sent periodically by routers on all interfaces */
struct pim_hello {
    uint16_t option_type;
    uint16_t option_len;
    union {
        uint16_t holdtime; /* the amount of time a receiver must keep the neighbour
                              reachable, in seconds */
        /*
         * The LAN Prune Delay option is used to tune the prune propagation delay on
         * multi-access LANs
         */
        struct {
            /*
             * Propagation delay and override interval are time intervals in units
             * of miliseconds. On a receiving router, the values of the fields are
             * used to tune the value of the Effective_Override_Interval(I) and its
             * derived timer values.
             */
            uint16_t prop_delay; /* Propagation delay. The first bit specifies the
                                    ability of the sending router to disable joins
                                    suppression */
            uint16_t override_interval;
        } lan_prune_delay;
        uint32_t dr_priority; /* Designated Router priority */
        uint32_t gen_id; /* Generation ID - random value for the interface on which
                            the Hello message is sent */
        struct {
            uint8_t version;
            uint8_t interval; /* the router's configured State Refresh Interval
                                 in seconds */
        } state_refresh;

        struct pim_unicast_addr *addr_list; /* the router's secondary addresses */
    };
};

/*
 * A register message is sent by the designated router or a PIM Multicast
 * Border Router to the rendezvous point when a multicast packet needs to be
 * transmitted on the RP-tree. The IP source address is set to the address of
 * the designated router, the destination address to the rendezvous point's
 * address. The IP TTL of the PIM packet is the system's normal unicast TTL.
 */
struct pim_register {
    unsigned int border : 1; /* the Border bit */
    unsigned int null : 1; /* the Null-Register bit */
    unsigned char *data; /* multicast data packet */
    unsigned int data_len;
};

/*
 * A Register-Stop is unicast from the RP to the sender of the Register
 * message. The IP source address is the address to which the register
 * was addressed. The IP destination address is the source address of
 * the register message.
 */
struct pim_register_stop {
    /* the group address from the multicast data packet in the register msg */
    struct pim_group_addr gaddr;

    /* the host address of the source from the multicast data packet in the
       register msg */
    struct pim_unicast_addr saddr;
};

/*
 * The assert message is used to resolve forwarder conflicts between
 * routers on a link. It is sent when a router receives a multicast
 * data packet on an interface on which the router would normally have
 * forwarded that packet. Assert messages may also be sent in response
 * to an assert message from another router.
 */
struct pim_assert {
    struct pim_group_addr gaddr;
    struct pim_unicast_addr saddr;

    /*
     * Preference value assigned to the unicast routing protocol that
     * provided the route to the multicast source or Rendezvous Point.
     * The first bit is the RPTbit. The RPTbit is set to 1 for
     * Assert(*,G) messages and 0 for Assert(S,G) messages
     */
    uint32_t metric_pref;

    /*
     * The unicast routing table metric associated with the route used
     * to reach the multicast source or Rendezvous Point. The metric
     * is in units applicable to the unicast routing protocol used.
     */
    uint32_t metric;
};

/*
 * A Join/Prune message is sent by routers towards upstream sources and
 * RPs. Joins are sent to build shared trees (RP trees) or source trees
 * (SPT). Prunes are sent to prune source trees when members leave
 * groups as well as sources that do not use the shared tree.
 */
struct pim_join_prune {
    /* primary address of the upstream neighbour that is the target of the message */
    struct pim_unicast_addr neighbour;

    uint8_t num_groups; /* number of multicast group sets contained in the message */
    uint16_t holdtime; /* the amount of time a receiver MUST keep the Join/Prune
                          state alive, in seconds */

    struct {
        struct pim_group_addr gaddr;

         /* number of joined source addresses listed for a given group */
        uint16_t num_joined_src;

         /* number of pruned source addresses listed for a given group */
        uint16_t num_pruned_src;

        /*
         * This list contains the sources for a given group that the
         * sending router will forward multicast datagrams from if
         * received on the interface on which the Join/Prune message
         * is sent.
         */
        struct pim_source_addr *joined_src;

        /*
         * This list contains the sources for a given group that the
         * sending router does not want to forward multicast datagrams
         * from when received on the interface on which the Join/Prune
         * message is sent.
         */
        struct pim_source_addr *pruned_src;
    } *groups;
};

struct pim_bootstrap {
    uint16_t tag; /* fragment tag -- acts to distinguish the fragments belonging
                     to different Bootstrap messages */
    uint8_t hash_len; /* the length (in bits) of the mask to use in the hash function */
    uint8_t priority; /* Bootstrap router (BSR) priority */
    struct pim_unicast_addr bsr_addr; /* address of the bootstrap router for the domain */

    struct {
        struct pim_group_addr gaddr;
        uint8_t rp_count; /* number of Candidate-RP addresses included in the whole
                             Bootstrap message for the corresponding group range */
        uint8_t frag_rp_count; /* number of Candidate-RP addresses included in this fragment
                                  of the Bootstrap message, for the corresponding group range */
        struct {
            struct pim_unicast_addr rp_addr;
            uint16_t holdtime; /* the holdtime (in seconds) for the corresponding RP */
            uint8_t priority;
        } *rps;
    } *groups;
};

struct pim_info {
    /* PIM header */
    unsigned int version : 4;
    unsigned int type : 4;
    uint16_t checksum;
    uint16_t len;

    union {
        unsigned char *hello;
        struct pim_register *reg;
        struct pim_register_stop *reg_stop;
        struct pim_assert *assert;
        struct pim_join_prune *jpg;
        struct pim_bootstrap *bootstrap;
    };
};

char *get_pim_message_type(uint8_t type);
list_t *parse_hello_options(struct pim_info *pim);

/*
 * Get the address in string format. This needs to be freed by the caller.
 * 'family' is the address family.
 * 'addr' is the address in byte format.
 */
char *get_pim_address(uint8_t family, unsigned char *addr);

/* internal to the decoder */
bool handle_pim(unsigned char *buffer, int n, struct pim_info *pim);
void free_pim_packet(struct pim_info *pim);

#endif
