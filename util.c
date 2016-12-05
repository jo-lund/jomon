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
#include "decoder/decoder.h"

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
    memcpy(buf + 8, info->sha, ETH_ALEN);
    memcpy(buf + 14, info->sip, 4);
    memcpy(buf + 18, info->tha, ETH_ALEN);
    memcpy(buf + 24, info->tip, 4);
}

void gethost(uint32_t addr, char *host, int hostlen)
{
    struct sockaddr_in saddr;

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = addr;
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

struct tm_t get_time(uint32_t num_secs)
{
    struct tm_t t;

    t.days = num_secs / (60 * 60 * 24);
    num_secs %= (60 * 60 * 24);
    t.hours = num_secs / (60 * 60);
    num_secs %= (60 * 60);
    t.mins = num_secs / 60;
    t.secs = num_secs % 60;
    return t;
}

void time_ntop(struct tm_t *time, char *result, int len)
{
    bool found = false;

    memset(result, 0, len);
    if (time->days) {
        snprintcat(result, len, time->days == 1 ? "%d day" : "%d days",
                   time->days);
        found = true;
    }
    if (time->hours) {
        if (found) {
            snprintcat(result, len, time->hours == 1 ? ", %d hour" : ", %d hours",
                       time->hours);
        } else {
            snprintcat(result, len, time->hours == 1 ? "%d hour" : "%d hours",
                       time->hours);
            found = true;
        }
    }
    if (time->mins) {
        if (found) {
            snprintcat(result, len, time->mins == 1 ? ", %d minute" :
                       ", %d minutes", time->mins);
        } else {
            snprintcat(result, len, time->mins == 1 ? "%d minute" :
                       "%d minutes", time->mins);
            found = true;
        }
    }
    if (time->secs) {
        if (found) {
            snprintcat(result, len, time->secs == 1 ? ", %d second" :
                       ", %d seconds", time->secs);
        } else {
            snprintcat(result, len, time->secs == 1 ? "%d second" :
                       "%d seconds", time->secs);
        }
    }
}
