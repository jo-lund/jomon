#ifndef PRINT_PROTOCOL_H
#define PRINT_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define ADDR_WIDTH 40
#define PROT_WIDTH 10
#define NUM_WIDTH 10
#define TIME_WIDTH 20

struct packet;
struct dns_info;
struct nbns_info;

/* write packet to buffer */
void pkt2text(char *buf, size_t size, const struct packet *p);

void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type);
void print_nbns_record(struct nbns_info *info, int i, char *buf, int n);

#endif
