#include <netinet/tcp.h>
#include <string.h>
#include "packet_tcp.h"
#include "packet_ip.h"

/* TCP Option-Kind */
#define TCP_OPT_END 0       /* end of options list */
#define TCP_OPT_NOP 1       /* no operation - this may be used to align option fields on
                               32-bit boundaries */
#define TCP_OPT_MSS 2       /* maximum segment size */
#define TCP_OPT_WIN_SCALE 3 /* window scale */
#define TCP_OPT_SAP 4       /* selective acknowledgement permitted */
#define TCP_OPT_SACK 5      /* selective acknowledgement */
#define TCP_OPT_TIMESTAMP 8 /* timestamp and echo of previous timestamp */

/*
 * TCP header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data | Res |N|C|E|U|A|P|R|S|F|                               |
 * | Offset|     |S|W|C|R|C|S|S|Y|I|            Window             |
 * |       |     | |R|E|G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Sequence Number: The sequence number of the first data octet in this segment (except
 *                  when SYN is present). If SYN is present the sequence number is the
 *                  initial sequence number (ISN) and the first data octet is ISN+1.
 * Ack Number: If the ACK control bit is set this field contains the value of the
 *             next sequence number the sender of the segment is expecting to
 *             receive. Once a connection is established this is always sent.
 * Data Offset: The number of 32 bits words in the TCP header. This indicates where the
 *              data begins.
 * Res: Reserved. Must be zero.
 * Control bits:
 *
 * NS: ECN-nonce concealment protection (experimental: see RFC 3540)
 * CWR: Congestion Window Reduced (CWR) flag is set by the sending host to
 *      indicate that it received a TCP segment with the ECE flag set and had
 *      responded in congestion control mechanism (added to header by RFC 3168).
 * ECE: ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
 *      If the SYN flag is set (1), that the TCP peer is ECN capable.
 *      If the SYN flag is clear (0), that a packet with Congestion Experienced flag set
 *      (ECN=11) in IP header received during normal transmission (added to header by
 *      RFC 3168).
 * URG: Urgent Pointer field significant
 * ACK: Acknowledgment field significant
 * PSH: Push Function
 * RST: Reset the connection
 * SYN: Synchronize sequence numbers
 * FIN: No more data from sender
 *
 * Window: The number of data octets beginning with the one indicated in the
 *         acknowledgment field which the sender of this segment is willing to accept.
 * Checksum: The checksum field is the 16 bit one's complement of the one's
 *           complement sum of all 16 bit words in the header and text.
 * Urgent Pointer: This field communicates the current value of the urgent pointer as a
 *            positive offset from the sequence number in this segment. The
 *            urgent pointer points to the sequence number of the octet following
 *            the urgent data. This field is only be interpreted in segments with
 *            the URG control bit set.
 */
bool handle_tcp(unsigned char *buffer, int n, struct ip_info *info)
{
    struct tcphdr *tcp;
    bool error;
    uint16_t payload_len;

    tcp = (struct tcphdr *) buffer;
    if (n < tcp->doff * 4) return false;

    info->tcp.src_port = ntohs(tcp->source);
    info->tcp.dst_port = ntohs(tcp->dest);
    info->tcp.seq_num = ntohl(tcp->seq);
    info->tcp.ack_num = ntohl(tcp->ack_seq);
    info->tcp.offset = tcp->doff;
    info->tcp.urg = tcp->urg;
    info->tcp.ack = tcp->ack;
    info->tcp.psh = tcp->psh;
    info->tcp.rst = tcp->rst;
    info->tcp.syn = tcp->syn;
    info->tcp.fin = tcp->fin;
    info->tcp.window = ntohs(tcp->window);
    info->tcp.checksum = ntohs(tcp->check);
    info->tcp.urg_ptr = ntohs(tcp->urg_ptr);

    /* the minimum header without options is 20 bytes */
    if (info->tcp.offset > 5) {
        uint8_t options_len;

        options_len = (info->tcp.offset - 5) * 4;
        info->tcp.options = malloc(options_len);
        memcpy(info->tcp.options, buffer + 20, options_len);
    } else {
        info->tcp.options = NULL;
    }
    payload_len = info->length - info->ihl * 4 - info->tcp.offset * 4;

    /* only check port if there is a payload */
    if (payload_len > 0) {
        for (int i = 0; i < 2; i++) {
            info->tcp.data.utype = *((uint16_t *) &info->tcp + i);
            if (check_port(buffer + info->tcp.offset * 4, &info->tcp.data, info->tcp.data.utype,
                           info->length - info->ihl * 4, &error)) {
                return true;
            }
        }
    }
    info->tcp.data.utype = 0;

    /* unknown application payload data */
    if (payload_len > 0) {
        info->tcp.data.payload = malloc(payload_len);
        info->tcp.data.payload_len = payload_len;
        memcpy(info->tcp.data.payload, buffer + info->tcp.offset * 4, payload_len);
    }
    return true;
}

struct tcp_options *parse_tcp_options(unsigned char *data, int len)
{
    struct tcp_options *opt;

    opt = calloc(1, sizeof(struct tcp_options));

    /* the data is based on a tag-length-value encoding scheme */
    while (len) {
        uint8_t option_kind = *data;
        uint8_t option_length = *++data; /* length of value + 1 byte tag and 1 byte length */

        switch (option_kind) {
        case TCP_OPT_END:
            return opt;
        case TCP_OPT_NOP:
            opt->nop++;
            break;
        case TCP_OPT_MSS:
            data++; /* skip length field */
            if (option_length == 4) {
                opt->mss = data[0] << 8 | data[1];
            }
            data += option_length - 2;
            break;
        case TCP_OPT_WIN_SCALE:
            data++; /* skip length field */
            if (option_length == 3) {
                opt->win_scale = *data;
            }
            data += option_length - 2;
            break;
        case TCP_OPT_SAP: /* 2 bytes */
            data++; /* skip length field */
            opt->sack_permitted = true;
            break;
        case TCP_OPT_SACK:
        {
            int num_blocks = (option_length - 2) / 8;
            struct tcp_sack_block *b;

            data++; /* skip length field */
            opt->sack = list_init(NULL);
            while (num_blocks--) {
                b = malloc(sizeof(struct tcp_sack_block));
                b->left_edge = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
                b->right_edge = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];
                list_push_back(opt->sack, b);
                data += 8; /* each block is 8 bytes */
            }
            break;
        }
        case TCP_OPT_TIMESTAMP:
            data++; /* skip length field */
            if (option_length == 10) {
                opt->ts_val = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
                opt->ts_ecr = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];
            }
            data += option_length - 2;
            break;
        }
        len -= option_length;
    }
    return opt;
}

void free_tcp_options(struct tcp_options *options)
{
    if (options->sack) list_free(options->sack);
    free(options);
}
