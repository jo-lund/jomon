#ifndef PACKET_H
#define PACKET_H

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdbool.h>
#include "../list.h"
#include "packet_dns.h"
#include "packet_nbns.h"
#include "packet_icmp.h"
#include "packet_igmp.h"
#include "packet_http.h"
#include "packet_arp.h"
#include "packet_stp.h"

#define ETHERNET_HDRLEN 14

enum port {
    DNS = 53,   /* Domain Name Service */
    HTTP = 80,  /* Hypertext Transfer Protocol */
    /*
     * NetBIOS is used for SMB/CIFS-based Windows file sharing. SMB can now run
     * Directly over TCP port 445, so NetBIOS is used for legacy support. Newer
     * Windows system can use DNS for all the purposes for which NBNS was used
     * previously.
     */
    NBNS = 137, /* NetBIOS Name Service */
    NBDS = 138, /* NetBIOS Datagram Service */
    NBSS = 139, /* NetBIOS Session Service */
    SSDP = 1900 /* Simple Service Discovery Protocol */
};

enum packet_type {
    UNKNOWN = -1,
    ETHERNET
};

struct application_info {
    uint16_t utype; /* specifies the application layer protocol */
    uint16_t payload_len;
    bool unknown_payload;
    union {
        struct dns_info *dns;
        struct nbns_info *nbns;
        struct http_info *http;
        list_t *ssdp;
        unsigned char *payload;
    };
};

struct udp_info {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len; /* length of UDP header and data */
    uint16_t checksum;
    struct application_info data;
};

struct tcp {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    unsigned int offset : 4;
    unsigned int ns  : 1;
    unsigned int cwr : 1;
    unsigned int ece : 1;
    unsigned int urg : 1;
    unsigned int ack : 1;
    unsigned int psh : 1;
    unsigned int rst : 1;
    unsigned int syn : 1;
    unsigned int fin : 1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
    unsigned char *options;
    struct application_info data;
};

// TODO: Improve the structure of this
struct ip_info {
    unsigned int version : 4;
    unsigned int ihl     : 4; /* Internet Header Length */
    unsigned int dscp    : 6; /* Differentiated Services Code Point (RFC 2474) */
    unsigned int ecn     : 2; /* Explicit congestion notification (RFC 3168) */
    uint16_t length; /* The entire packet size in bytes, including header and data */
    uint16_t id; /* Identification field, used for uniquely identifying group of fragments */
    uint16_t foffset; /* Fragment offset. The first 3 bits are flags.*/
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    bool unknown_payload;
    union {
        struct udp_info udp;
        struct tcp tcp;
        struct igmp_info igmp;
        struct icmp_info icmp;
        unsigned char *payload;
    };
};

/* 802.2 SNAP */
struct snap_info {
    unsigned char oui[3]; /* IEEE Organizationally Unique Identifier */
    uint16_t protocol_id; /* If OUI is 0 the protocol ID is the Ethernet type */
    bool unknown_payload;
    union {
        struct arp_info *arp;
        struct ip_info *ip;
        unsigned char *payload;
    };
};

/* Ethernet 802.2 Logical Link Control */
struct eth_802_llc {
    uint8_t dsap; /* destination service access point */
    uint8_t ssap; /* source service access point */
    uint8_t control; /* possible to be 2 bytes? */
    bool unknown_payload;
    union {
        struct snap_info *snap;
        struct stp_info *bpdu;
        unsigned char *payload;
    };
};

struct eth_info {
    unsigned char mac_src[ETH_ALEN];
    unsigned char mac_dst[ETH_ALEN];
    uint16_t ethertype;
    bool unknown_payload;
    union {
        struct eth_802_llc *llc;
        struct arp_info *arp;
        struct ip_info *ip;
        unsigned char *payload;
    };
};

/*
 * Generic packet structure that can be used for every type of packet. For now
 * only support for Ethernet.
 */
struct packet {
    enum packet_type ptype;
    uint32_t num;
    struct eth_info eth;
};

/*
 * Get a packet from the network interface card. Will allocate enough memory
 * for packet, which needs to be freed with free_packet.
 */
size_t read_packet(int sockfd, unsigned char *buffer, size_t n, struct packet **p);

/*
 * Decodes the data in buffer and stores a pointer to the decoded packet, which
 * has to be freed by calling free_packet.
 *
 * Returns true if decoding succeeded, else false.
 */
bool decode_packet(unsigned char *buffer, size_t n, struct packet **p);

/* Free the memory allocated for packet */
void free_packet(void *packet);

#endif
