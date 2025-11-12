#ifndef PACKET_IP6_H
#define PACKET_IP6_H

#include <stdbool.h>

#define IPV6_FIXED_HEADER_LEN 40

struct packet_data;
struct packet;

/*
 * Parse 'count' number of ip6 addresses from buffer and store them in 'addrs'.
 * Return the new length of buffer.
 */
int parse_ipv6_addr(uint8_t *addrs, int count, unsigned char **buf, int n);

void register_ip6(void);
bool is_ipv6(struct packet_data *pdata);


#endif
