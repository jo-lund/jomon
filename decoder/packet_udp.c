#include <netinet/udp.h>
#include <string.h>
#include "packet_udp.h"
#include "packet_ip.h"

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
packet_error handle_udp(unsigned char *buffer, int n, struct udp_info *info)
{
    if (n < UDP_HDR_LEN) return UDP_ERR;

    struct udphdr *udp;
    packet_error error;

    pstat[PROT_UDP].num_packets++;
    pstat[PROT_UDP].num_bytes += n;
    udp = (struct udphdr *) buffer;
    info->src_port = ntohs(udp->source);
    info->dst_port = ntohs(udp->dest);
    info->len = ntohs(udp->len);
    info->checksum = ntohs(udp->check);

    for (int i = 0; i < 2; i++) {
        info->data.utype = *((uint16_t *) info + i);
        if (check_port(buffer + UDP_HDR_LEN, n - UDP_HDR_LEN, &info->data,
                       info->data.utype, &error)) {
            return error;
        }
    }
    info->data.utype = 0; /* unknown application protocol */
    return NO_ERR;
}
