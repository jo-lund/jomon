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
#include "../interface.h"

#define DATALINK 0
#define ETH802_3 1
#define ETHERNET_II 2
#define IP_PROTOCOL 3
#define PORT 4

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
    SMTP = 25,  /* Simple Message Transport Protocol */
    DNS = 53,   /* Domain Name System */
    DHCP_SRV = 67, /* Dynamic Host Configuration Protocol Server/BOOTP server */
    DHCP_CLI = 68, /* Dynamic Host Configuration Protocol Client/BOOTP client */
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
    SMB = 445,       /* Server Message Block */
    SMTPS = 465,     /* Transport Layer Security (SMTPS) */
    SMTP_EMS = 587,  /* Email Message Submission (SMTP) */
    IMAPS = 993,     /* Transport Layer Security (IMAPS) */
    SSDP = 1900,     /* Simple Service Discovery Protocol */
    SMTP_ALT = 3535, /* SMTP alternate */
    MDNS = 5353,     /* Multicast DNS */
    LLMNR = 5355     /* Link-Local Multicast Name Resolution */
};

enum transport {
    TCP,
    UDP
};

typedef enum {
    NO_ERR,
    DECODE_ERR,
    DATALINK_ERR,
    UNK_PROTOCOL,
} packet_error;

struct packet_data;

struct protocol_info {
    char *short_name;
    char *long_name;
    uint64_t num_bytes;
    uint32_t num_packets;
    packet_error (*decode)(struct protocol_info *pinfo, unsigned char *buf, int n,
                           struct packet_data *p);
    void (*print_pdu)(char *buf, int n, void *data);
    void (*add_pdu)(void *w, void *sw, void *data);
};

typedef void (*protocol_handler)(struct protocol_info *pinfo, void *arg);

/*
 * Generic packet structure that can be used for every type of packet.
 */
struct packet {
    uint32_t num;
    packet_error perr;
    struct timeval time;
    unsigned char *buf; /* contains the frame as seen on the network */
    unsigned int len;
    struct packet_data *root;
};

struct packet_data {
    uint32_t id;
    uint8_t transport;
    uint16_t len;
    void *data;
    struct packet_data *prev;
    struct packet_data *next;
};

/* TODO: move this */
void decoder_init(void);
void decoder_exit(void);
void register_protocol(struct protocol_info *pinfo, uint16_t layer, uint16_t id);
struct protocol_info *get_protocol(uint32_t id);
void traverse_protocols(protocol_handler fn, void *arg);

/*
 * Decodes the data in buffer and stores it in struct packet, which has to be
 * freed by calling free_packets.
 *
 * Returns true if decoding succeeded, else false.
 */
bool decode_packet(iface_handle_t *handle, unsigned char *buffer, size_t n,
                   struct packet **p);

/*
 * Frees data and everything allocated more recently than data. To free the
 * whole pool, i.e. all the packets, use NULL as argument.
 */
void free_packets(void *data);

/* Return a pointer to the application payload */
unsigned char *get_adu_payload(struct packet *p);

/* Return the payload length */
unsigned int get_adu_payload_len(struct packet *p);

/* Clear packet statistics */
void clear_statistics(void);

bool is_tcp(struct packet *p);

struct packet_data *get_packet_data(const struct packet *p, uint32_t id);

/* Should be internal to the decoder */
packet_error call_data_decoder(uint32_t id, struct packet_data *pdata,
                               uint8_t transport, unsigned char *buf, int n);

static inline uint32_t get_protocol_id(uint16_t layer, uint16_t key)
{
    return (layer << 16) | key;
}

static inline uint16_t get_protocol_layer(uint32_t id)
{
    return id >> 16;
}

static inline uint16_t get_protocol_key(uint32_t id)
{
    return id & 0xffff;
}

#endif
