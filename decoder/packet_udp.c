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
bool handle_udp(unsigned char *buffer, int n, struct udp_info *info)
{
    if (n < UDP_HDR_LEN) return false;

    struct udphdr *udp;
    bool error;

    udp = (struct udphdr *) buffer;
    info->src_port = ntohs(udp->source);
    info->dst_port = ntohs(udp->dest);
    info->len = ntohs(udp->len);
    info->checksum = ntohs(udp->check);

    for (int i = 0; i < 2; i++) {
        info->data.utype = *((uint16_t *) info + i);
        if (check_port(buffer + UDP_HDR_LEN, n - UDP_HDR_LEN, &info->data,
                       info->data.utype, &error)) {
            return true;
        }
    }
    info->data.utype = 0;

    /* unknown application payload data */
    if (info->len - UDP_HDR_LEN > 0) {
        info->data.payload_len = info->len - UDP_HDR_LEN;
        info->data.payload = malloc(info->data.payload_len);
        memcpy(info->data.payload, buffer + UDP_HDR_LEN, info->data.payload_len);
    }
    return true;
}
