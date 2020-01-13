#include <netinet/ip_icmp.h>
#include "packet_ip.h"
#include "packet_icmp.h"

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
    register_protocol(&icmp_prot, LAYER3, IPPROTO_ICMP);
}

packet_error handle_icmp(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    if (n < ICMP_HDR_LEN) return ICMP_ERR;

    struct icmp_info *info;
    struct icmp *icmp = (struct icmp *) buffer;

    info = mempool_pealloc(sizeof(struct icmp_info));
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
    case ICMP_REDIRECT:
        info->gateway = icmp->icmp_gwaddr.s_addr;
        break;
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
        info->echo.id = ntohs(icmp->icmp_id);
        info->echo.seq_num = ntohs(icmp->icmp_seq);
        info->timestamp.originate = ntohl(icmp->icmp_otime);
        info->timestamp.receive = ntohl(icmp->icmp_rtime);
        info->timestamp.transmit = ntohl(icmp->icmp_ttime);
        break;
    case ICMP_ADDRESS:
    case ICMP_ADDRESSREPLY:
        info->echo.id = ntohs(icmp->icmp_id);
        info->echo.seq_num = ntohs(icmp->icmp_seq);
        info->addr_mask = icmp->icmp_mask;
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
    case ICMP_DEST_UNREACH:
        return "Destination Unreachable";
    case ICMP_SOURCE_QUENCH:
        return "Source Quench";
    case ICMP_REDIRECT:
        return "Redirect (change route)";
    case ICMP_ECHO:
        return "Echo Request";
    case ICMP_TIME_EXCEEDED:
        return "Time Exceeded";
    case ICMP_PARAMETERPROB:
        return "Parameter Problem";
    case ICMP_TIMESTAMP:
        return "Timestamp Request";
    case ICMP_TIMESTAMPREPLY:
        return "Timestamp Reply";
    case ICMP_INFO_REQUEST:
        return "Information Request";
    case ICMP_INFO_REPLY:
        return "Information Reply";
    case ICMP_ADDRESS:
        return "Address Mask Request";
    case ICMP_ADDRESSREPLY:
        return "Address Mask Reply";
    default:
        return "";
    }
}

char *get_icmp_dest_unreach_code(uint8_t code)
{
    switch (code) {
    case ICMP_NET_UNREACH:
        return "Network Unreachable";
    case ICMP_HOST_UNREACH:
        return "Host Unreachable";
    case ICMP_PROT_UNREACH:
        return "Protocol Unreachable";
    case ICMP_PORT_UNREACH:
        return "Port Unreachable";
    case ICMP_FRAG_NEEDED:
        return "Fragmentation Needed/DF set";
    case ICMP_SR_FAILED:
        return "Source Route failed";
    case ICMP_PKT_FILTERED:
        return "Packet filtered";
    case ICMP_PREC_VIOLATION:
        return "Precedence violation";
    case ICMP_PREC_CUTOFF:
        return "Precedence cut off";
    default:
        return "";
    }
}

char *get_icmp_redirect_code(uint8_t code)
{
    switch (code) {
    case ICMP_REDIR_NET:
        return "Redirect for the network";
    case ICMP_REDIR_HOST:
        return "Redirect for the host";
    case ICMP_REDIR_NETTOS:
        return "Redirect for the type of service and network";
    case ICMP_REDIR_HOSTTOS:
        return "Redirect for the type of service and host";
    default:
        return "";
    }
}
