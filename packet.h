#ifndef PACKET_H
#define PACKET_H

#include <netinet/in.h>

/* hardware address length (format aa:bb:cc:dd:ee:ff) */
#define HW_ADDRSTRLEN 18

#define UDP_HDRLEN 8

/* DNS opcodes */
#define QUERY 0  /* standard query */
#define IQUERY 1 /* inverse query */
#define STATUS 2 /* server status request */

/* DNS response codes */
#define NO_ERROR 0         /* no error condition */
#define FORMAT_ERROR 1     /* name server was unable to interpret the query */
#define SERVER_FAILURE 2   /* name server was unable to process the query */
#define NAME_ERROR 3       /* the domain name referenced in the query does not exist */
#define NOT_IMPLEMENTED 4  /* name server does not support the request kind of query */
#define REFUSED 5          /* name server refuses to perform the specified operation */

struct arp_info {
    char sip[INET_ADDRSTRLEN]; /* sender IP address */
    char tip[INET_ADDRSTRLEN]; /* target IP address */
    char sha[HW_ADDRSTRLEN];   /* sender hardware address */
    char tha[HW_ADDRSTRLEN];   /* target hardware address */
    uint16_t op;               /* ARP opcode */
};

struct ip_info {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    uint8_t protocol;
    union {
        struct {
            uint16_t src_port;
            uint16_t dst_port;
            struct {
                // TODO: Make into bit fields. QR should only be one bit.
                int8_t qr; /* -1 not DNS, 0 DNS query, 1 DNS response */
                uint8_t opcode; // 4 bits
                uint8_t rcode; // 4 bits
            } dns;
        } udp;
        struct {
            uint16_t src_port;
            uint16_t dst_port;
        } tcp;
    };
};

/* get a packet from the network interface card */
void read_packet(int sockfd);

#endif
