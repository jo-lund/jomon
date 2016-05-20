#include "packet.h"

#define ADDR_WIDTH 36
#define PROT_WIDTH 10

/* write packet to buffer */
void print_buffer(char *buf, int size, struct packet *p);

void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type, bool *soa);
void print_nbns_record(struct nbns_info *info, int i, char *buf, int n, uint16_t type);
