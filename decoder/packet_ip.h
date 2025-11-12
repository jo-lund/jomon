#ifndef PACKET_IP_H
#define PACKET_IP_H

#include <stdbool.h>

struct packet_data;
struct packet;

/*
 * IP Differentiated Services Code Point class selectors.
 * Prior to DiffServ, IPv4 networks could use the Precedence field in the TOS
 * byte of the IPv4 header to mark priority traffic. In order to maintain
 * backward compatibility with network devices that still use the Precedence
 * field, DiffServ defines the Class Selector PHB.
 *
 * The Class Selector code points are of the form 'xxx000'. The first three bits
 * are the IP precedence bits. Each IP precedence value can be mapped into a
 * DiffServ class. CS0 equals IP precedence 0, CS1 IP precedence 1, and so on.
 * If a packet is received from a non-DiffServ aware router that used IP
 * precedence markings, the DiffServ router can still understand the encoding as
 * a Class Selector code point.
 */
#define CS0 0X0
#define CS1 0X8
#define CS2 0X10
#define CS3 0X18
#define CS4 0X20
#define CS5 0X28
#define CS6 0X30
#define CS7 0X38

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
