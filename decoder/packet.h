#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "../list.h"
#include "packet_ethernet.h"

struct packet_flags {
    char *str;
    int width;
    char **sflags;
};

struct packet_statistics {
    uint32_t num_packets;
    uint32_t num_arp;
    uint32_t num_stp;
    uint32_t num_ip;
    uint32_t num_ip6;
    uint32_t num_icmp;
    uint32_t num_igmp;
    uint32_t num_pim;
    uint32_t num_tcp;
    uint32_t num_udp;
    uint32_t num_dns;
    uint32_t num_mdns;
    uint32_t num_http;
    uint32_t num_nbns;
    uint32_t num_ssdp;
    uint64_t tot_bytes;
    uint64_t bytes_arp;
    uint64_t bytes_stp;
    uint64_t bytes_ip;
    uint64_t bytes_ip6;
    uint64_t bytes_icmp;
    uint64_t bytes_igmp;
    uint64_t bytes_pim;
    uint64_t bytes_tcp;
    uint64_t bytes_udp;
    uint64_t bytes_dns;
    uint64_t bytes_mdns;
    uint64_t bytes_http;
    uint64_t bytes_nbns;
    uint64_t bytes_ssdp;
};

extern struct packet_statistics pstat;

enum port {
    DNS = 53,   /* Domain Name Service */
    HTTP = 80,  /* Hypertext Transfer Protocol */
    /*
     * NetBIOS is used for SMB/CIFS-based Windows file sharing. SMB can now run
     * Directly over TCP port 445, so NetBIOS is used for legacy support. Newer
     * Windows system can use DNS for all the purposes for which NBNS was used
     * previously.
     */
    NBNS = 137,  /* NetBIOS Name Service */
    NBDS = 138,  /* NetBIOS Datagram Service */
    NBSS = 139,  /* NetBIOS Session Service */
    SSDP = 1900, /* Simple Service Discovery Protocol */
    MDNS = 5353  /* Multicast DNS */
};

enum packet_type {
    UNKNOWN = -1,
    ETHERNET
};

struct application_info {
    uint16_t utype; /* specifies the application layer protocol */
    union {
        struct dns_info *dns;
        struct nbns_info *nbns;
        struct http_info *http;
        list_t *ssdp;
    };
};

/*
 * Generic packet structure that can be used for every type of packet. For now
 * only support for Ethernet.
 */
struct packet {
    enum packet_type ptype;
    uint32_t num;
    struct timeval time;
    struct eth_info eth;
};

/*
 * Get a packet from the network interface card. Will allocate enough memory
 * for packet, which needs to be freed with free_packet.
 */
size_t read_packet(int sockfd, unsigned char *buffer, size_t len, struct packet **p);

/*
 * Decodes the data in buffer and stores a pointer to the decoded packet, which
 * has to be freed by calling free_packet.
 *
 * Returns true if decoding succeeded, else false.
 */
bool decode_packet(unsigned char *buffer, size_t n, struct packet **p);

/* Free the memory allocated for packet */
void free_packet(void *packet);

/* Return a pointer to the application payload */
unsigned char *get_adu_payload(struct packet *p);

/* Clear packet statistics */
void clear_statistics();

/* Should be internal to the decoder */
bool check_port(unsigned char *buffer, int n, struct application_info *info,
                uint16_t port, bool *error);


#endif
