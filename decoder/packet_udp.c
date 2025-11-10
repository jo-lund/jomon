#include <sys/types.h>
#include <netinet/udp.h>
#include <string.h>
#include "packet_udp.h"
#include "packet_ip.h"
#include "util.h"

extern void print_udp(char *buf, int n, void *data);

static struct protocol_info udp_prot = {
    .short_name = "UDP",
    .long_name = "User Datagram Protocol",
    .decode = handle_udp,
    .print_pdu = print_udp,
};

void register_udp(void)
{
    register_protocol(&udp_prot, IP4_PROT, IPPROTO_UDP);
    register_protocol(&udp_prot, IP6_PROT, IPPROTO_UDP);
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
    packet_error error = NO_ERR;
    struct udp_info *udp;

    udp = mempool_alloc(sizeof(struct udp_info));
    if (n < UDP_HDR_LEN) {
        memset(udp, 0, sizeof(*udp));
        pdata->len = n;
        pdata->error = create_error_string("Packet length (%d) less than UDP header length (%d)",
                                           n, UDP_HDR_LEN);
        return DECODE_ERR;
    }
    pdata->len = UDP_HDR_LEN;
    udp->sport = read_uint16be(&buffer);
    udp->dport = read_uint16be(&buffer);
    udp->len = read_uint16be(&buffer);
    udp->checksum = read_uint16be(&buffer);
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    if (udp->len < UDP_HDR_LEN) {
        pdata->error = create_error_string("UDP length (%d) less than minimum header length (%d)",
                                           udp->len, UDP_HDR_LEN);
        return DECODE_ERR;
    }
    if (udp->len > n) {
        pdata->error = create_error_string("UDP length (%d) greater than packet length (%d)",
                                           udp->len, n);
        return DECODE_ERR;
    }
    if (n - UDP_HDR_LEN > 0) {
        for (int i = 0; i < 2; i++) {
            error = call_data_decoder(get_protocol_id(PORT, *((uint16_t *) udp + i)),
                                      pdata, IPPROTO_UDP, buffer, n - UDP_HDR_LEN);
            if (error != UNK_PROTOCOL)
                return NO_ERR;
        }
    }
    return NO_ERR;
}
