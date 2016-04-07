#ifndef UTIL_H
#define UTIL_H

struct arp_info;

// TODO: This should be moved to its own file. Will be used for injecting
// packets.

void serialize_arp(unsigned char *buf, struct arp_info *info);

/*
 * Get host name from addr which is in dotted-decimal format. This will send a
 * DNS request over UDP.
 */
void gethost(char *addr, char *host, int hostlen);

/*
 * Concatenate fmt string to buf. Will never print passed the size of buf.
 * Expects buf to already contain a string or that buf is zeroed.
 *
 * Returns the number of bytes written.
 */
int snprintcat(char *buf, int size, char *fmt, ...);

const char *get_arp_hardware_type(uint16_t type);
const char *get_arp_protocol_type(uint16_t type);
const char *get_arp_opcode(uint16_t opcode);
const char *get_dns_opcode(uint8_t opcode);
const char *get_dns_rcode(uint8_t rcode);
const char *get_dns_type(uint16_t type);
const char *get_dns_type_extended(uint16_t type);
const char *get_dns_class(uint16_t class);
const char *get_dns_class_extended(uint16_t class);

#endif
