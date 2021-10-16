#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "packet_ip.h"
#include "packet_icmp.h"
#include "../attributes.h"

#define ICMP_HDR_LEN 8

extern void add_icmp_information(void *w, void *sw, void *data);
extern void print_icmp(char *buf, int n, void *data);

static struct protocol_info icmp_prot = {
    .short_name = "ICMP",
    .long_name = "Internet Control Message Protocol",
    .decode = handle_icmp,
    .print_pdu = print_icmp,
    .add_pdu = add_icmp_information
};

void register_icmp()
{
    register_protocol(&icmp_prot, IP_PROTOCOL, IPPROTO_ICMP);
}

packet_error handle_icmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    if (n < ICMP_HDR_LEN) return DECODE_ERR;

    struct icmp_info *info;
    struct icmp *icmp = (struct icmp *) buffer;

    info = mempool_alloc(sizeof(struct icmp_info));
    pdata->data = info;
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    info->type = icmp->icmp_type;
    info->code = icmp->icmp_code;
    info->checksum = htons(icmp->icmp_cksum);
    switch (icmp->icmp_type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        info->echo.id = ntohs(icmp->icmp_id);
        info->echo.seq_num = ntohs(icmp->icmp_seq);
        break;
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        info->echo.id = ntohs(icmp->icmp_id);
        info->echo.seq_num = ntohs(icmp->icmp_seq);
        info->timestamp.originate = ntohl(icmp->icmp_otime);
        info->timestamp.receive = ntohl(icmp->icmp_rtime);
        info->timestamp.transmit = ntohl(icmp->icmp_ttime);
        break;
    case ICMP_MASKREQ:
    case ICMP_MASKREPLY:
        info->echo.id = ntohs(icmp->icmp_id);
        info->echo.seq_num = ntohs(icmp->icmp_seq);
        info->addr_mask = icmp->icmp_mask;
        break;
    case ICMP_PARAMPROB:
        info->pointer = icmp->icmp_pptr;
        goto parse_ip;
    case ICMP_REDIRECT:
        info->gateway = icmp->icmp_gwaddr.s_addr;
        FALLTHROUGH;
    case ICMP_UNREACH:
    case ICMP_TIMXCEED:
    case ICMP_SOURCEQUENCH:
    parse_ip:
        if (n > ICMP_HDR_LEN) {
            struct protocol_info *pinfo;

            pdata->id = get_protocol_id(ETHERNET_II, ETHERTYPE_IP);
            pinfo = get_protocol(pdata->id);
            pdata->next = mempool_calloc(struct packet_data);
            return pinfo->decode(pinfo, buffer + ICMP_HDR_LEN, n - ICMP_HDR_LEN, pdata->next);
        }
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
