#include <netinet/ip_icmp.h>
#include "packet_ip.h"
#include "packet_icmp.h"

#define ICMP_HDR_LEN 8

/*
 * ICMP message format:
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             unused                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Internet Header + 64 bits of Original Data Datagram      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The ICMP header is 8 bytes.
 */
bool handle_icmp(unsigned char *buffer, int n, struct icmp_info *info)
{
    if (n < ICMP_HDR_LEN) return false;

    struct icmp *icmp = (struct icmp *) buffer;

    pstat[PROT_ICMP].num_packets++;
    pstat[PROT_ICMP].num_bytes += n;
    info->type = icmp->icmp_type;
    info->code = icmp->icmp_code;
    info->checksum = htons(icmp->icmp_cksum);
    switch (icmp->icmp_type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        info->echo.id = ntohs(icmp->icmp_id);
        info->echo.seq_num = ntohs(icmp->icmp_seq);
        break;
    case ICMP_DEST_UNREACH:
        break;
    default:
        break;
    }
    return true;
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
