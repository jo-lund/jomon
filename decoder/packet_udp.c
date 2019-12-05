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
                        void *data)
{
    if (n < UDP_HDR_LEN) return UDP_ERR;

    struct udphdr *udp;
    packet_error error;
    struct eth_info *eth = data;
    struct udp_info *info;

    if (eth->ethertype == ETH_P_IP) {
        eth->ipv4->udp = mempool_pealloc(sizeof(struct udp_info));
        info = eth->ipv4->udp;
    } else {
        eth->ipv6->udp = mempool_pealloc(sizeof(struct udp_info));
        info = eth->ipv6->udp;
    }
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    udp = (struct udphdr *) buffer;
    info->src_port = ntohs(udp->source);
    info->dst_port = ntohs(udp->dest);
    info->len = ntohs(udp->len);
    if (info->len < UDP_HDR_LEN || info->len > n) {
        return UDP_ERR;
    }
    info->checksum = ntohs(udp->check);
    for (int i = 0; i < 2; i++) {
        info->data.utype = *((uint16_t *) info + i);
        info->data.transport = UDP;
        error = check_port(buffer + UDP_HDR_LEN, n - UDP_HDR_LEN, &info->data,
                           info->data.utype);
        if (error != UNK_PROTOCOL) {
            return error;
        }
    }
    info->data.utype = 0; /* unknown application protocol */
    return error;
}
