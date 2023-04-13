#ifndef PRINT_PROTOCOL_H
#define PRINT_PROTOCOL_H

#include <stdint.h>

#define ADDR_WIDTH 40
#define PROT_WIDTH 10
#define NUM_WIDTH 10
#define TIME_WIDTH 20
#define HOSTNAMELEN 255 /* maximum 255 according to rfc1035 */

struct packet;
struct dns_info;
struct nbns_info;

/* write packet to buffer */
void write_to_buf(char *buf, int size, struct packet *p);

/*
 * Convert the network address 'src' into a string in 'dst', or store the
 * host name if that is available.
 */
void get_name_or_address(const uint32_t src, char *dst);

void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type);
void print_nbns_record(struct nbns_info *info, int i, char *buf, int n);

#endif
