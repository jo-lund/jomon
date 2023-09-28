#ifndef PRINT_ETH_H
#define PRINT_ETH_H

struct dns_info;
struct nbns_info;

void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type);
void print_nbns_record(struct nbns_info *info, int i, char *buf, int n);

#endif
