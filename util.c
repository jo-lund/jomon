#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <netinet/ip_icmp.h>
#include <linux/igmp.h>
#include "util.h"
#include "vector.h"
#include "error.h"
#include "decoder/packet.h"

/*
 * Transform a hex string in the format aa:bb:cc:dd:ee:ff to its integer
 * representation stored in a char array of size 6.
 */
static bool hextoint(unsigned char dest[], char *src)
{
    if (strlen(src) != HW_ADDRSTRLEN) return false;

    uint8_t res;
    char *end;
    int i = 0;

    do {
        errno = 0;
        res = strtoul(src, &end, 16);
        if ((errno != 0 && res == 0) || (i < 5 && *end != ':')) {
            return false;
        }
        dest[i++] = res;
        src += 3;
    } while (*end != '\0' && i < 6);

    return true;
}

void serialize_arp(unsigned char *buf, struct arp_info *info)
{
    /* ARP header */
    buf[0] = info->ht >> 8;
    buf[1] = info->ht & 0x00ff;
    buf[2] = info->pt >> 8;
    buf[3] = info->pt & 0x00ff;
    buf[4] = info->hs;
    buf[5] = info->ps;
    buf[6] = info->op >> 8;
    buf[7] = info->op & 0x00ff;

    /* ARP payload */
    hextoint(buf + 8, info->sha);
    inet_pton(AF_INET, info->sip, buf + 14);
    hextoint(buf + 18, info->tha);
    inet_pton(AF_INET, info->tip, buf + 24);
}

void gethost(char *addr, char *host, int hostlen)
{
    struct sockaddr_in saddr;
    struct in_addr naddr;

    inet_pton(AF_INET, addr, &naddr);
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr = naddr;
    getnameinfo((struct sockaddr *) &saddr, sizeof(struct sockaddr_in),
                host, hostlen, NULL, 0, 0);
}

int snprintcat(char *buf, int size, char *fmt, ...)
{
    va_list ap;
    int len;
    int n;

    len = strnlen(buf, size);
    va_start(ap, fmt);
    n = vsnprintf(buf + len, size - len, fmt, ap);
    va_end(ap);
    return n;
}

char *strtolower(char *str)
{
    char *ptr = str;

    while (*ptr != '\0') {
        *ptr = tolower(*ptr);
        ptr++;
    }
    return str;
}

int get_max_namelen(struct dns_resource_record *record, int n)
{
    int maxlen = 0;

    for (int i = 0; i < n; i++) {
        int len = strlen(record[i].name);
        if (len > maxlen) {
            maxlen = len;
        }
    }
    return maxlen;
}
