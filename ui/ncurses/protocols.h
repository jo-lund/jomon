#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include "list_view.h"

struct packet_flags;

/*
 * Display the bit values of flags
 *
 * 'flags' contains the flag values
 * 'num_flags' is the size of packet_flags
 * 'packet_flag' is an array that contains a name/description of the specific flag,
 * its width (which is the number of bits in the flag), and, based on the value of
 * the flag, a description of the specific field value, see decoder/packet.h.
 */
void add_flags(list_view *lw, list_view_header *header, uint32_t flags,
               struct packet_flags *pf, int num_flags);

#endif
