#ifndef AF_H
#define AF_H

#include <stdint.h>

/* Address family numbers, cf. RFC1700 */
#define AF_IP 1
#define AF_IP6 2
#define AF_NSAP 3
#define AF_HDLC 4
#define AF_BBN_1822 5
#define AF_802 6
#define AF_E163 7
#define AF_E164 8
#define AF_F69 9
#define AF_X121 10
#define AF_IP_X 11
#define AF_ATALK 12
#define AF_DECNET 13
#define AF_BANYAN_VINES 14

/* BSD/MAC AF values */
#define AF_BSD_INET 2
#define AF_FREEBSD_INET6 28
#define AF_DARWIN_INET6 30

char *get_address_family(uint32_t family);
char *get_bsd_address_family(uint32_t family);

#endif
