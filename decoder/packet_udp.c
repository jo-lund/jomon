#include <netinet/udp.h>
#include <string.h>
#include "packet_udp.h"
#include "packet_ip.h"

#define UDP_HDR_LEN 8

/*
 * UDP header
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Length             |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
bool handle_udp(unsigned char *buffer, int n, struct ip_info *info)
{
    if (n < UDP_HDR_LEN) return false;

    struct udphdr *udp;
    bool error;

    udp = (struct udphdr *) buffer;
    info->udp.src_port = ntohs(udp->source);
    info->udp.dst_port = ntohs(udp->dest);
    info->udp.len = ntohs(udp->len);
    info->udp.checksum = ntohs(udp->check);

    for (int i = 0; i < 2; i++) {
        info->udp.data.utype = *((uint16_t *) &info->udp + i);
        if (check_port(buffer + UDP_HDR_LEN, &info->udp.data, info->udp.data.utype,
                       info->udp.len - UDP_HDR_LEN, &error)) {
            return true;
        }
    }
    info->udp.data.utype = 0;

    /* unknown application payload data */
    if (info->udp.len - UDP_HDR_LEN > 0) {
        info->udp.data.payload = malloc(info->udp.len - UDP_HDR_LEN);
        info->udp.data.payload_len = info->udp.len - UDP_HDR_LEN;
        memcpy(info->udp.data.payload, buffer + UDP_HDR_LEN, info->udp.data.payload_len);
    }
    return true;
}
