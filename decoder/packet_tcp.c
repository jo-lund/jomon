#include <netinet/tcp.h>
#include <string.h>
#include "packet_tcp.h"
#include "packet_ip.h"
#include "tcp_analyzer.h"
#include "util.h"
#include "debug.h"

#define MIN_HEADER_LEN 20

static struct packet_flags tcp_flags[] = {
    { "Reserved", 3, NULL },
    { "NS: ECN nonce concealment protection", 1, NULL },
    { "CWR: Congestion Window Reduced", 1, NULL },
    { "ECE: ECN echo", 1, NULL },
    { "URG: Urgent pointer", 1, NULL },
    { "ACK: Acknowledgment", 1, NULL },
    { "PSH: Push function", 1, NULL },
    { "RST: Reset the connection", 1, NULL },
    { "SYN: Synchronize sequence numbers", 1, NULL },
    { "FIN: No more data", 1, NULL}
};

extern void add_tcp_information(void *w, void *sw, void *data);
extern void print_tcp(char *buf, int n, void *data);

static struct protocol_info tcp_prot = {
    .short_name = "TCP",
    .long_name = "Transmission Control Protocol",
    .decode = handle_tcp,
    .print_pdu = print_tcp,
    .add_pdu = add_tcp_information
};

void register_tcp(void)
{
    register_protocol(&tcp_prot, IP4_PROT, IPPROTO_TCP);
    register_protocol(&tcp_prot, IP6_PROT, IPPROTO_TCP);
}


static packet_error parse_tcp_options(struct tcp *tcp, unsigned char *data, int len)
{
    struct tcp_options **opt;

    opt = &tcp->opt;
    while (len > 0) {
        *opt = mempool_calloc(1, struct tcp_options);
        (*opt)->option_kind = *data;
        switch ((*opt)->option_kind) {
        case TCP_OPT_END:
            if (len < 2)
                goto error;
            (*opt)->option_length = *++data;
            return NO_ERR;
        case TCP_OPT_NOP:
            data++;
            (*opt)->option_length = 1; /* NOP only contains the kind byte */
            break;
        case TCP_OPT_MSS:
            if (len < 4 || ((*opt)->option_length = data[1]) != 4)
                goto error;
            data += 2;
            (*opt)->mss = read_uint16be(&data);
            break;
        case TCP_OPT_WIN_SCALE:
            if (len < 3 || ((*opt)->option_length = data[1]) != 3)
                goto error;
            data += 2;
            (*opt)->win_scale = *data;
            data += (*opt)->option_length - 2;
            break;
        case TCP_OPT_SAP: /* 2 bytes */
            if (len < 2 || ((*opt)->option_length = data[1]) != 2)
                goto error;
            data += 2;
            (*opt)->sack_permitted = true;
            break;
        case TCP_OPT_SACK:
        {
            int num_blocks;
            struct tcp_sack_block *b;

            if (len < 2 || ((*opt)->option_length = data[1]) < 10)
                goto error;
            data += 2;
            num_blocks = ((*opt)->option_length - 2) / 8;
            if (len < num_blocks * 8)
                goto error;
            (*opt)->sack = list_init(&d_alloc);
            while (num_blocks--) {
                b = mempool_alloc(sizeof(struct tcp_sack_block));
                b->left_edge = read_uint32be(&data);
                b->right_edge = read_uint32be(&data);
                list_push_back((*opt)->sack, b);
            }
            break;
        }
        case TCP_OPT_TIMESTAMP:
            if (len < 10 || ((*opt)->option_length = data[1]) != 10)
                goto error;
            data += 2;
            (*opt)->ts.ts_val = read_uint32be(&data);
            (*opt)->ts.ts_ecr = read_uint32be(&data);
            break;
        case TCP_OPT_TFO:
            if (len < 2)
                goto error;
            (*opt)->option_length = data[1];
            if (len < (*opt)->option_length || (*opt)->option_length > 18 ||
                (*opt)->option_length < 6)
                goto error;
            data += 2;
            (*opt)->cookie = data;
            data += (*opt)->option_length - 2;
            break;
        default:
            DEBUG("TCP option %d not supported", (*opt)->option_kind);
            (*opt)->option_length = data[1];
            if (len < 2 ||  (*opt)->option_length > len || (*opt)->option_length == 0)
                goto error;
            data += (*opt)->option_length;
            break;
        }
        len -= (*opt)->option_length;
        opt = &(*opt)->next;
    }
    return NO_ERR;

error:
    if (*opt) {
        mempool_free(*opt);
        *opt = NULL;
    }
    return DECODE_ERR;
}


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
packet_error handle_tcp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata)
{
    packet_error error = NO_ERR;
    uint16_t payload_len;
    struct tcp *tcp;
    unsigned char *p;

    tcp = mempool_alloc(sizeof(struct tcp));
    pdata->data = tcp;
    if (n < MIN_HEADER_LEN) {
        memset(tcp, 0, sizeof(*tcp));
        pdata->len = n;
        pdata->error = create_error_string("Packet length (%d) less than minimum TCP header length (%d)",
                                           n, MIN_HEADER_LEN);
        return DECODE_ERR;
    }
    p = buffer;
    tcp->sport = read_uint16be(&p);
    tcp->dport = read_uint16be(&p);
    tcp->seq_num = read_uint32be(&p);
    tcp->ack_num = read_uint32be(&p);
    tcp->offset = p[0] >> 4;
    tcp->ns = p[0] & 0x1;
    tcp->cwr = (p[1] & 0x80) >> 7;
    tcp->ece = (p[1] & 0x40) >> 6;
    tcp->urg = (p[1] & TH_URG) >> 5;
    tcp->ack = (p[1] & TH_ACK) >> 4;
    tcp->psh = (p[1] & TH_PUSH) >> 3;
    tcp->rst = (p[1] & TH_RST) >> 2;
    tcp->syn = (p[1] & TH_SYN) >> 1;
    tcp->fin = (p[1] & TH_FIN);
    p += 2;
    tcp->window = read_uint16be(&p);
    tcp->checksum = read_uint16be(&p);
    tcp->urg_ptr = read_uint16be(&p);
    tcp->opt = NULL;
    payload_len = n - tcp->offset * 4;
    pdata->len = tcp->offset * 4;
    pinfo->num_packets++;
    pinfo->num_bytes += n;

    /* bogus header length */
    if (tcp->offset < 5) {
        pdata->error = create_error_string("TCP data offset (%d) less than minimum value (5)",
                                           tcp->offset);
        return DECODE_ERR;
    }
    if (n < tcp->offset * 4) {
        pdata->error = create_error_string("Packet length (%d) less than TCP header (%d)",
                                           n, tcp->offset * 4);
        return DECODE_ERR;
    }

    /* the minimum header without options is 20 bytes */
    if (tcp->offset > 5) {
        uint8_t options_len;

        options_len = (tcp->offset - 5) * 4;
        if (parse_tcp_options(tcp, buffer + (p - buffer), options_len) != NO_ERR) {
            if (tcp->opt) {
                mempool_free(tcp->opt);
                tcp->opt = NULL;
            }
            pdata->error = create_error_string("TCP options error");
            return DECODE_ERR;
        }
    }
    if (payload_len > 0) {
        for (int i = 0; i < 2; i++) {
            error = call_data_decoder(get_protocol_id(PORT, *((uint16_t *) tcp + i)), pdata,
                                      IPPROTO_TCP, buffer + tcp->offset * 4, payload_len);
            if (error != UNK_PROTOCOL)
                return NO_ERR;
        }
    }
    return NO_ERR;
}

struct packet_flags *get_tcp_flags(void)
{
    return tcp_flags;
}

int get_tcp_flags_size(void)
{
    return sizeof(tcp_flags) / sizeof(struct packet_flags);
}
