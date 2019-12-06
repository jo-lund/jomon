#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include "../list.h"
#include "packet_ethernet.h"
#include "../mempool.h"
#include "../alloc.h"

#define LAYER802_3 0
#define LAYER2 1
#define LAYER3 2
#define LAYER4 3

extern uint32_t total_packets;
extern uint64_t total_bytes;

struct packet_flags {
    char *str;     /* flag description */
    int width;     /* number of bits in the field */
    char **sflags; /* description of field indexed by bit value */
};

// TODO: move this to an internal header
extern allocator_t d_alloc;

enum port {
    DNS = 53,   /* Domain Name System */
    HTTP = 80,  /* Hypertext Transfer Protocol */
    /*
     * NetBIOS is used for SMB/CIFS-based Windows file sharing. SMB can now run
     * Directly over TCP port 445, so NetBIOS is used for legacy support. Newer
     * Windows system can use DNS for all the purposes for which NBNS was used
     * previously.
     */
    NBNS = 137,      /* NetBIOS Name Service */
    NBDS = 138,      /* NetBIOS Datagram Service */
    NBSS = 139,      /* NetBIOS Session Service */
    IMAP = 143,      /* Internet Message Access Protocol */
    SNMP = 161,      /* Simple Network Management Protocol */
    SNMPTRAP = 162,  /* Simple Network Management Protocol Trap */
    HTTPS = 443,     /* Transport Layer Security (HTTPS) */
    IMAPS = 993,     /* Transport Layer Security (IMAPS) */
    SSDP = 1900,     /* Simple Service Discovery Protocol */
    MDNS = 5353,     /* Multicast DNS */
    LLMNR = 5355     /* Link-Local Multicast Name Resolution */
};

enum transport {
    TCP,
    UDP
};

typedef enum {
    UNKNOWN = -1,
    ETHERNET
} packet_type;

typedef enum {
    NO_ERR,
    UNK_PROTOCOL,
    ETH_ERR,
    ARP_ERR,
    STP_ERR,
    IPv4_ERR,
    IPv6_ERR,
    ICMP_ERR,
    IGMP_ERR,
    PIM_ERR,
    TCP_ERR,
    UDP_ERR,
    DNS_ERR,
    NBNS_ERR,
    NBDS_ERR,
    HTTP_ERR,
    SSDP_ERR,
    SNMP_ERR,
    SMB_ERR,
    IMAP_ERR,
    TLS_ERR
} packet_error;

struct protocol_info {
    char *short_name;
    char *long_name;
    uint64_t num_bytes;
    uint32_t num_packets;
    packet_error (*decode)(struct protocol_info *pinfo, unsigned char *buf, int n,
                           void *data);
    void (*print_pdu)(char *buf, int n, void *data);
    void (*add_pdu)(void *w, void *sw, void *data);
};

typedef void (*protocol_handler)(struct protocol_info *pinfo, void *arg);

struct application_info {
    uint8_t transport;
    uint16_t utype; /* specifies the application layer protocol */
    union {
        struct dns_info *dns;
        struct nbns_info *nbns;
        struct nbds_info *nbds;
        struct http_info *http;
        struct snmp_info *snmp;
        struct imap_info *imap;
        struct ssdp_info *ssdp;
        struct tls_info *tls;
    };
};

/*
 * Generic packet structure that can be used for every type of packet. For now
 * only support for Ethernet.
 */
struct packet {
    packet_type ptype;
    uint32_t num;
    packet_error perr;
    struct timeval time;
    struct eth_info eth;
};

/* TODO: move this */
void decoder_init();
void decoder_exit();
void register_protocol(struct protocol_info *pinfo, int layer, uint16_t id);
struct protocol_info *get_protocol(int layer, uint16_t id);
void traverse_protocols(protocol_handler fn, void *arg);

/*
 * Decodes the data in buffer and stores it in struct packet, which has to be
 * freed by calling free_packets.
 *
 * Returns true if decoding succeeded, else false.
 */
bool decode_packet(unsigned char *buffer, size_t n, struct packet **p);

/*
 * Frees data and everything allocated more recently than data. To free the
 * whole pool, i.e. all the packets, use NULL as argument.
 */
void free_packets(void *data);

/* Return a pointer to the application payload */
unsigned char *get_adu_payload(struct packet *p);

struct application_info *get_adu_info(struct packet *p);

/* Clear packet statistics */
void clear_statistics();

uint16_t get_packet_size(struct packet *p);

bool is_tcp(struct packet *p);

/* Should be internal to the decoder */
packet_error check_port(unsigned char *buffer, int n, struct application_info *adu,
                        uint16_t port);

#endif
