#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "packet_ip.h"
#include "packet_icmp.h"
#include "attributes.h"
#include "util.h"

#define ICMP_HDR_LEN 8

static packet_error handle_icmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                                struct packet_data *pdata);
extern void add_icmp_information(void *w, void *sw, void *data);
extern void print_icmp(char *buf, int n, void *data);

static struct protocol_info icmp_prot = {
    .short_name = "ICMP",
    .long_name = "Internet Control Message Protocol",
    .decode = handle_icmp,
    .print_pdu = print_icmp,
    .add_pdu = add_icmp_information
};

void register_icmp(void)
{
    register_protocol(&icmp_prot, IP_PROTOCOL, IPPROTO_ICMP);
}

packet_error handle_icmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    if (n < ICMP_HDR_LEN)
        return UNK_PROTOCOL;

    struct icmp_info *icmp;

    icmp = mempool_alloc(sizeof(struct icmp_info));
    pdata->data = icmp;
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    icmp->type = *buffer++;
    icmp->code = *buffer++;
    icmp->checksum = read_uint16be(&buffer);
    switch (icmp->type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        icmp->id = read_uint16be(&buffer);
        icmp->seq_num = read_uint16be(&buffer);
        if (n > ICMP_HDR_LEN) {
            icmp->echo.data = buffer;
            icmp->echo.len = n - ICMP_HDR_LEN;
        } else {
            icmp->echo.data = NULL;
            icmp->echo.len = 0;
        }
        break;
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        icmp->id = read_uint16be(&buffer);
        icmp->seq_num = read_uint16be(&buffer);
        if (n - ICMP_HDR_LEN < 12) {
            icmp->timestamp.originate = 0;
            icmp->timestamp.receive = 0;
            icmp->timestamp.transmit = 0;
            pdata->error = create_error_string("ICMP packet too short (%d)", n);
            return DECODE_ERR;
        }
        icmp->timestamp.originate = read_uint32be(&buffer);
        icmp->timestamp.receive = read_uint32be(&buffer);
        icmp->timestamp.transmit = read_uint32be(&buffer);
        break;
    case ICMP_MASKREQ:
    case ICMP_MASKREPLY:
        icmp->id = read_uint16be(&buffer);
        icmp->seq_num = read_uint16be(&buffer);
        if (n - ICMP_HDR_LEN < 4) {
            pdata->error = create_error_string("ICMP packet too short (%d)", n);
            return DECODE_ERR;
        }
        /* store in big endian format */
        icmp->addr_mask = read_uint32le(&buffer);
        break;
    case ICMP_PARAMPROB:
        icmp->pointer = buffer[0];
        goto parse_ip;
    case ICMP_REDIRECT:
        /* store in big endian format */
        icmp->gateway = get_uint32le(buffer);
        FALLTHROUGH;
    case ICMP_UNREACH:
    case ICMP_TIMXCEED:
    case ICMP_SOURCEQUENCH:
    parse_ip:
        if (n > ICMP_HDR_LEN) {
            struct protocol_info *pinfo;
            uint32_t id;

            id = get_protocol_id(ETHERNET_II, ETHERTYPE_IP);
            pinfo = get_protocol(id);
            pdata->next = mempool_calloc(1, struct packet_data);
            pdata->next->id = id;
            /* buffer points on ICMP header + 4, i.e. need to add 4 bytes to get at data */
            return pinfo->decode(pinfo, buffer + 4, n - ICMP_HDR_LEN, pdata->next);
        }
        break;
    case ICMP_INFO_REQUEST:
    case ICMP_INFO_REPLY:
        icmp->id = read_uint16be(&buffer);
        icmp->seq_num = read_uint16be(&buffer);
        break;
    default:
        break;
    }
    return NO_ERR;
}

char *get_icmp_type(uint8_t type)
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

char *get_icmp_dest_unreach_code(uint8_t code)
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

char *get_icmp_redirect_code(uint8_t code)
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
