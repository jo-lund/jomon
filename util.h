#ifndef UTIL_H
#define UTIL_H

struct arp_info;

// TODO: This should be moved to its own file. Will be used for
// injecting packets.
void serialize_arp(unsigned char *buf, struct arp_info *info);

const char *get_arp_hardware_type(uint16_t type);
const char *get_arp_protocol_type(uint16_t type);
const char *get_arp_opcode(uint16_t opcode);

#endif
