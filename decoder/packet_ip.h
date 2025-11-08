#ifndef PACKET_IP_H
#define PACKET_IP_H

#include <stdbool.h>

struct packet_data;
struct packet;

/* internal to the decoder */
void register_ip(void);

/* Get the string representation of the IPv4/IPv6 transport protocol */
char *get_ip_transport_protocol(uint8_t protocol);

/*
 * Parse 'count' number of ip addresses from buffer and store them in 'addrs'.
 * Return the new length of buffer.
 */
int parse_ipv4_addr(uint32_t *addrs, int count, unsigned char **buf, int n);

bool is_ipv4(struct packet_data *pdata);
uint32_t ipv4_src(const struct packet *p);
uint32_t ipv4_dst(const struct packet *p);

#endif
