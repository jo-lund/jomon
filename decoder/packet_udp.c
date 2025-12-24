#include <sys/types.h>
#include <netinet/udp.h>
#include <string.h>
#include <stdio.h>
#include "packet.h"
#include "packet_udp.h"
#include "packet_ip.h"
#include "util.h"
#include "field.h"

#define UDP_HDR_LEN 8

static void print_udp(char *buf, int n, struct packet_data *pdata);
static packet_error handle_udp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                               struct packet_data *pdata);

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
    uint16_t length;

    if (n < UDP_HDR_LEN) {
        pdata->len = n;
        pdata->error = create_error_string("Packet length (%d) less than UDP header length (%d)",
                                           n, UDP_HDR_LEN);
        return DECODE_ERR;
    }
    pdata->len = UDP_HDR_LEN;
    pdata->data = field_init();
    field_add_value(pdata->data, "Source port", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buffer)));
    field_add_value(pdata->data, "Destination port", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buffer)));
    length = read_uint16be(&buffer);
    field_add_value(pdata->data, "Length", FIELD_UINT16, UINT_TO_PTR(length));
    field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buffer)));
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    if (length < UDP_HDR_LEN) {
        field_finish(pdata->data);
        pdata->error = create_error_string("UDP length (%d) less than minimum header length (%d)",
                                           length, UDP_HDR_LEN);
        return DECODE_ERR;
    }
    if (length > n) {
        field_finish(pdata->data);
        pdata->error = create_error_string("UDP length (%d) greater than packet length (%d)",
                                           length, n);
        return DECODE_ERR;
    }
    field_finish(pdata->data);
    if (n - UDP_HDR_LEN > 0) {
        for (int i = 0; i < 2; i++) {
            error = call_data_decoder(get_protocol_id(PORT, field_get_uint16(field_get(pdata->data, i))),
                                      pdata, IPPROTO_UDP, buffer, n - UDP_HDR_LEN);
            if (error != UNK_PROTOCOL)
                return NO_ERR;
        }
    }
    return NO_ERR;
}

void print_udp(char *buf, int n, struct packet_data *pdata)
{
    snprintf(buf, n, "Source port: %u  Destination port: %u",
             field_get_uint16(field_get(pdata->data, 0)),
             field_get_uint16(field_get(pdata->data, 1)));
}
