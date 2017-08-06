#ifndef PACKET_SSDP_H
#define PACKET_SSDP_H

#include <stdbool.h>
#include <stdint.h>
#include "packet.h"

struct application_info;

/* internal to the decoder */
packet_error handle_ssdp(unsigned char *buffer, int n, struct application_info *info);

#endif
