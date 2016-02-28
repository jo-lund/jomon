#ifndef PACKET_H
#define PACKET_H

#include <netinet/in.h>

/* hardware address length (format aa:bb:cc:dd:ee:ff) */
#define HRDW_ADDRSTRLEN 18

struct arp_info {
    char sip[INET_ADDRSTRLEN]; /* sender IP address */
    char tip[INET_ADDRSTRLEN]; /* target ip address */
    char sha[HRDW_ADDRSTRLEN]; /* sender hardware address */
    char tha[HRDW_ADDRSTRLEN]; /* target hardware address */
    uint16_t op; /* ARP opcode */
};

struct ip_info {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
};

/* get a packet from the network interface card */
void read_packet(int sockfd);

#endif
