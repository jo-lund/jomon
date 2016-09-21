#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include "list.h"

struct arp_info;
struct dns_resource_record;

// TODO: This should be moved to its own file. Will be used for injecting
// packets.
void serialize_arp(unsigned char *buf, struct arp_info *info);

/*
 * Get host name from addr which is in dotted-decimal format. This will send a
 * DNS request over UDP.
 */
void gethost(char *addr, char *host, int hostlen);

/*
 * Concatenates fmt string to buf. Will never print passed the size of buf.
 * Expects buf to already contain a string or that buf is zeroed.
 *
 * Returns the number of bytes written.
 */
int snprintcat(char *buf, int size, char *fmt, ...);

/* Converts str to lower case */
char *strtolower(char *str);

/* Get the size of the longest domain name in the RRs */
int get_max_namelen(struct dns_resource_record *record, int n);

// TODO: Simplify this.
/* Convert type to string */
char *get_arp_hardware_type(uint16_t type);
char *get_arp_protocol_type(uint16_t type);
char *get_arp_opcode(uint16_t opcode);
char *get_icmp_dest_unreach_code(uint8_t code);
char *get_icmp_type(uint8_t type);
char *get_igmp_type(uint8_t type);
char *get_stp_bpdu_type(uint8_t type);
char *get_transport_protocol(uint8_t protocol);

#endif
