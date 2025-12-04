#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "packet_ip.h"
#include "packet_icmp.h"
#include "attributes.h"
#include "util.h"
#include "field.h"
#include "string.h"

#define ICMP_HDR_LEN 8

#ifdef __FreeBSD__
#define ICMP_INFO_REQUEST ICMP_IREQ
#define ICMP_INFO_REPLY ICMP_IREQREPLY
#endif

static packet_error handle_icmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                                struct packet_data *pdata);
static void print_icmp(char *buf, int n, struct packet_data *pdata);

static struct protocol_info icmp_prot = {
    .short_name = "ICMP",
    .long_name = "Internet Control Message Protocol",
    .decode = handle_icmp,
    .print_pdu = print_icmp,
};

void register_icmp(void)
{
    register_protocol(&icmp_prot, IP4_PROT, IPPROTO_ICMP);
    register_protocol(&icmp_prot, IP6_PROT, IPPROTO_ICMP);
}

static char *get_icmp_type(uint8_t type)
{
    switch (type) {
    case ICMP_ECHOREPLY:
        return "Echo Reply";
    case ICMP_UNREACH:
        return "Destination Unreachable";
    case ICMP_SOURCEQUENCH:
        return "Source Quench";
    case ICMP_REDIRECT:
        return "Redirect (change route)";
    case ICMP_ECHO:
        return "Echo Request";
    case ICMP_TIMXCEED:
        return "Time Exceeded";
    case ICMP_PARAMPROB:
        return "Parameter Problem";
    case ICMP_TSTAMP:
        return "Timestamp Request";
    case ICMP_TSTAMPREPLY:
        return "Timestamp Reply";
    case ICMP_IREQ:
        return "Information Request";
    case ICMP_IREQREPLY:
        return "Information Reply";
    case ICMP_MASKREQ:
        return "Address Mask Request";
    case ICMP_MASKREPLY:
        return "Address Mask Reply";
    default:
        return "";
    }
}

static char *get_icmp_dest_unreach_code(uint8_t code)
{
    switch (code) {
    case ICMP_UNREACH_NET:
        return "Network Unreachable";
    case ICMP_UNREACH_HOST:
        return "Host Unreachable";
    case ICMP_UNREACH_PROTOCOL:
        return "Protocol Unreachable";
    case ICMP_UNREACH_PORT:
        return "Port Unreachable";
    case ICMP_UNREACH_NEEDFRAG:
        return "Fragmentation Needed/DF set";
    case ICMP_UNREACH_SRCFAIL:
        return "Source Route failed";
    case ICMP_UNREACH_FILTER_PROHIB:
        return "Packet filtered";
    case ICMP_UNREACH_HOST_PRECEDENCE:
        return "Precedence violation";
    case ICMP_UNREACH_PRECEDENCE_CUTOFF:
        return "Precedence cut off";
    default:
        return "";
    }
}

static char *get_icmp_redirect_code(uint8_t code)
{
    switch (code) {
    case ICMP_REDIRECT_NET:
        return "Redirect for the network";
    case ICMP_REDIRECT_HOST:
        return "Redirect for the host";
    case ICMP_REDIRECT_TOSNET:
        return "Redirect for the type of service and network";
    case ICMP_REDIRECT_TOSHOST:
        return "Redirect for the type of service and host";
    default:
        return "";
    }
}

packet_error handle_icmp(struct protocol_info *pinfo, unsigned char *buf, int n,
                         struct packet_data *pdata)
{
    struct uint_string type, code;

    if (n < ICMP_HDR_LEN)
        return UNK_PROTOCOL;

    pdata->data = field_init();
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    type.val = *buf++;
    type.str = get_icmp_type(type.val);
    field_add_value(pdata->data, "Type", FIELD_UINT_STRING, &type);
    switch (type.val) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Identifier", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Sequence number", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buf)));
        if (n > ICMP_HDR_LEN)
            field_add_bytes(pdata->data, "Data", FIELD_BYTES, buf, n - ICMP_HDR_LEN);
        break;
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Identifier", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Sequence number", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buf)));
        if (n - ICMP_HDR_LEN < 12) {
            pdata->error = create_error_string("ICMP packet too short (%d)", n);
            return DECODE_ERR;
        }
        field_add_value(pdata->data, "Originate timestamp", FIELD_TIMESTAMP,
                        UINT_TO_PTR(read_uint32be(&buf)));
        field_add_value(pdata->data, "Receive timestamp", FIELD_TIMESTAMP,
                        UINT_TO_PTR(read_uint32be(&buf)));
        field_add_value(pdata->data, "Transmit timestamp", FIELD_TIMESTAMP,
                        UINT_TO_PTR(read_uint32be(&buf)));
        break;
    case ICMP_MASKREQ:
    case ICMP_MASKREPLY:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Identifier", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Sequence number", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buf)));
        if (n - ICMP_HDR_LEN < 4) {
            pdata->error = create_error_string("ICMP packet too short (%d)", n);
            return DECODE_ERR;
        }
        /* store in big endian format */
        field_add_value(pdata->data, "Address mask", FIELD_IP4ADDR, UINT_TO_PTR(read_uint32le(&buf)));
        break;
    case ICMP_PARAMPROB:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(buf[0]));
        goto parse_ip;
    case ICMP_REDIRECT:
        code.val = *buf++;
        code.str = get_icmp_redirect_code(code.val);
        field_add_value(pdata->data, "Code", FIELD_UINT_STRING, &code);
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        /* store in big endian format */
        field_add_value(pdata->data, "Redirect", FIELD_IP4ADDR, UINT_TO_PTR(get_uint32le(buf)));
        goto parse_ip;
    case ICMP_UNREACH:
        code.val = *buf++;
        code.str = get_icmp_dest_unreach_code(code.val);
        field_add_value(pdata->data, "Code", FIELD_UINT_STRING, &code);
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        goto parse_ip;
    case ICMP_TIMXCEED:
    case ICMP_SOURCEQUENCH:
        field_add_value(pdata->data, "Code", FIELD_UINT_STRING, &code);
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
    parse_ip:
        if (n > ICMP_HDR_LEN) {
            struct protocol_info *p;
            uint32_t id;

            id = get_protocol_id(ETHERNET_II, ETHERTYPE_IP);
            p = get_protocol(id);
            field_finish(pdata->data);
            pdata->next = mempool_calloc(1, struct packet_data);
            pdata->next->id = id;
            /* buffer points at ICMP header + 4, i.e. need to add 4 bytes to get at data */
            return p->decode(p, buf + 4, n - ICMP_HDR_LEN, pdata->next);
        }
        break;
    case ICMP_INFO_REQUEST:
    case ICMP_INFO_REPLY:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Identifier", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Sequence number", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buf)));
        break;
    default:
        break;
    }
    field_finish(pdata->data);
    return NO_ERR;
}

void print_icmp(char *buf, int n, struct packet_data *pdata)
{
#if 0
    const struct field *f;
    struct uint_string *type, *code;
    uint16_t id, seq;
    char addr[INET_ADDRSTRLEN];
    uint32_t gateway;
    char org[32];
    char rcvd[32];
    char xmit[32];
    uint32_t originate, receive, transmit;

    type = field_search_value(pdata->data, "Type");
    switch (type->val) {
    case ICMP_ECHOREPLY:
        f = field_search(pdata->data, "Identifier");
        id = field_get_uint16(f);
        f = field_search(pdata->data, "Sequence number");
        seq = field_get_uint16(f);
        snprintf(buf, n, "Echo reply:   id = 0x%x  seq = %d", id, seq);
        break;
    case ICMP_ECHO:
        f = field_search(pdata->data, "Identifier");
        id = field_get_uint16(f);
        f = field_search(pdata->data, "Sequence number");
        seq = field_get_uint16(f);
        snprintf(buf, n, "Echo request: id = 0x%x  seq = %d", id, seq);
        break;
    case ICMP_UNREACH:
        code = field_search_value(pdata->data, "Code");
        snprintf(buf, n, "%s", code->str);
        break;
    case ICMP_REDIRECT:
        f = field_search(pdata->data, "Redirect");
        gateway = field_get_uint32(f);
        inet_ntop(AF_INET, &gateway, addr, INET_ADDRSTRLEN);
        snprintf(buf, n, "Redirect to %s", addr);
        break;
    case ICMP_TSTAMP:
        f = field_search(pdata->data, "Identifier");
        id = field_get_uint16(f);
        f = field_search(pdata->data, "Sequence number");
        seq = field_get_uint16(f);
        f = field_search(pdata->data, "Originate timestamp");
        originate = field_get_uint32(f);
        f = field_search(pdata->data, "Receive timestamp");
        receive = field_get_uint32(f);
        f = field_search(pdata->data, "Transmit timestamp");
        transmit = field_get_uint32(f);
        snprintf(buf, n, "Timestamp request: id = 0x%x  seq = %d, originate = %s, receive = %s, transmit = %s",
                 id, seq, get_time_from_ms_ut(originate, org, 32), get_time_from_ms_ut(receive, rcvd, 32),
                 get_time_from_ms_ut(transmit, xmit, 32));
        break;
    case ICMP_TSTAMPREPLY:
        f = field_search(pdata->data, "Identifier");
        id = field_get_uint16(f);
        f = field_search(pdata->data, "Sequence number");
        seq = field_get_uint16(f);
        f = field_search(pdata->data, "Originate timestamp");
        originate = field_get_uint32(f);
        f = field_search(pdata->data, "Receive timestamp");
        receive = field_get_uint32(f);
        f = field_search(pdata->data, "Transmit timestamp");
        transmit = field_get_uint32(f);
        snprintf(buf, n, "Timestamp reply:   id = 0x%x  seq = %d, originate = %s, receive = %s, transmit = %s",
                 id, seq, get_time_from_ms_ut(originate, org, 32), get_time_from_ms_ut(receive, rcvd, 32),
                 get_time_from_ms_ut(transmit, xmit, 32));
        break;
    case ICMP_MASKREQ:
        f = field_search(pdata->data, "Identifier");
        id = field_get_uint16(f);
        f = field_search(pdata->data, "Sequence number");
        seq = field_get_uint16(f);
        f = field_search(pdata->data, "Address mask");
        gateway = field_get_uint32(f);
        inet_ntop(AF_INET, &gateway, addr, INET_ADDRSTRLEN);
        snprintf(buf, n, "Address mask request: id = 0x%x  seq = %d, mask = %s", id, seq, addr);
        break;
    case ICMP_MASKREPLY:
        f = field_search(pdata->data, "Identifier");
        id = field_get_uint16(f);
        f = field_search(pdata->data, "Sequence number");
        seq = field_get_uint16(f);
        f = field_search(pdata->data, "Address mask");
        gateway = field_get_uint32(f);
        inet_ntop(AF_INET, &gateway, addr, INET_ADDRSTRLEN);
        snprintf(buf, n, "Address mask reply:   id = 0x%x  seq = %d, mask = %s", id, seq, addr);
        break;
    default:
        snprintf(buf, n, "%s", type->str);
    }
#endif
}
