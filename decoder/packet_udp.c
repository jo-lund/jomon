#include <netinet/udp.h>
#include <string.h>
#include "packet_udp.h"
#include "packet_ip.h"

extern void add_udp_information(void *w, void *sw, void *data);
extern void print_udp(char *buf, int n, void *data);

static struct protocol_info udp_prot = {
    .short_name = "UDP",
    .long_name = "User Datagram Protocol",
    .decode = handle_udp,
    .print_pdu = print_udp,
    .add_pdu = add_udp_information
};

void register_udp()
{
    register_protocol(&udp_prot, LAYER3, IPPROTO_UDP);
}

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
packet_error handle_udp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata)
{
    if (n < UDP_HDR_LEN) return DECODE_ERR;

    struct udphdr *udp;
    packet_error error = NO_ERR;
    struct udp_info *info;

    info = mempool_pealloc(sizeof(struct udp_info));
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    udp = (struct udphdr *) buffer;
    info->src_port = ntohs(udp->source);
    info->dst_port = ntohs(udp->dest);
    info->len = ntohs(udp->len);
    if (info->len < UDP_HDR_LEN || info->len > n) {
        return DECODE_ERR;
    }
    info->checksum = ntohs(udp->check);
    pdata->data = info;
    pdata->len = UDP_HDR_LEN;
    for (int i = 0; i < 2; i++) {
        pdata->id = *((uint16_t *) info + i);
        error = call_data_decoder(pdata, UDP, buffer + UDP_HDR_LEN, n - UDP_HDR_LEN);
        if (error != UNK_PROTOCOL) {
            return error;
        }
    }
    return error;
}
