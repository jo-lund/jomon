#ifndef AF_H
#define AF_H

#include <stdint.h>

/* Address family numbers, cf. RFC1700 */
#define AFN_IP 1
#define AFN_IP6 2
#define AFN_NSAP 3
#define AFN_HDLC 4
#define AFN_BBN_1822 5
#define AFN_802 6
#define AFN_E163 7
#define AFN_E164 8
#define AFN_F69 9
#define AFN_X121 10
#define AFN_IP_X 11
#define AFN_ATALK 12
#define AFN_DECNET 13
#define AFN_BANYAN_VINES 14

/* BSD/MAC AF values */
#define AFN_BSD_INET 2
#define AFN_FREEBSD_INET6 28
#define AFN_DARWIN_INET6 30

char *get_address_family(uint32_t family);
char *get_bsd_address_family(uint32_t family);

#endif
