#include <arpa/inet.h>
#include <net/if_arp.h>
#include <linux/igmp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include "output.h"
#include "ui_protocols.h"
#include "util.h"

#define HOSTNAMELEN 255 /* maximum 255 according to rfc1035 */

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define PRINT_ADDRESS(buffer, n, src, dst)                              \
    snprintf(buffer, n, "%-" STR(ADDR_WIDTH) "s" "%-" STR(ADDR_WIDTH) "s", src, dst)
#define PRINT_PROTOCOL(buffer, n, prot)                     \
    snprintcat(buffer, n, "%-" STR(PROT_WIDTH) "s", prot)
#define PRINT_INFO(buffer, n, fmt, ...)         \
    snprintcat(buffer, n, fmt, ## __VA_ARGS__)
#define PRINT_LINE(buffer, n, src, dst, prot, fmt, ...)   \
    do {                                                  \
        PRINT_ADDRESS(buffer, n, src, dst);               \
        PRINT_PROTOCOL(buffer, n, prot);                  \
        PRINT_INFO(buffer, n, fmt, ## __VA_ARGS__);       \
    } while (0)

static void print_arp(char *buf, int n, struct arp_info *info);
static void print_ip(char *buf, int n, struct ip_info *info);
static void print_udp(char *buf, int n, struct ip_info *info);
static void print_tcp(char *buf, int n, struct ip_info *info);
static void print_icmp(char *buf, int n, struct ip_info *info);
static void print_igmp(char *buf, int n, struct ip_info *info);
static void print_dns(char *buf, int n, struct dns_info *dns);
static void print_nbns(char *buf, int n, struct nbns_info *nbns);
static void print_ssdp(char *buf, int n, list_t *ssdp);
static void print_http(char *buf, int n, struct http_info *http);

void print_buffer(char *buf, int size, struct packet *p)
{
    switch (p->eth.ethertype) {
    case ETH_P_ARP:
        print_arp(buf, size, p->eth.arp);
        break;
    case ETH_P_IP:
        print_ip(buf, size, p->eth.ip);
        break;
    default:
        break;
    }
}

/* print ARP frame information */
void print_arp(char *buf, int n, struct arp_info *info)
{
    switch (info->op) {
    case ARPOP_REQUEST:
        PRINT_LINE(buf, n, info->sip, info->tip, "ARP",
                   "Request: Looking for hardware address of %s", info->tip);
        break;
    case ARPOP_REPLY:
        PRINT_LINE(buf, n, info->sip, info->tip, "ARP",
                   "Reply: %s has hardware address %s", info->sip, info->sha);
        break;
    default:
        PRINT_LINE(buf, n, info->sip, info->tip, "ARP", "Opcode %d", info->op);
        break;
    }
}

/* print IP packet information */
void print_ip(char *buf, int n, struct ip_info *info)
{
    if (!numeric && (info->protocol != IPPROTO_UDP ||
                     (info->protocol == IPPROTO_UDP && info->udp.data.dns->qr == -1))) {
        char sname[HOSTNAMELEN];
        char dname[HOSTNAMELEN];

        /* get the host name of source and destination */
        gethost(info->src, sname, HOSTNAMELEN);
        gethost(info->dst, dname, HOSTNAMELEN);
        // TEMP: Fix this!
        sname[35] = '\0';
        dname[35] = '\0';
        PRINT_ADDRESS(buf, n, sname, dname);
    } else {
        PRINT_ADDRESS(buf, n, info->src, info->dst);
    }
    switch (info->protocol) {
    case IPPROTO_ICMP:
        print_icmp(buf, n, info);
        break;
    case IPPROTO_IGMP:
        print_igmp(buf, n, info);
        break;
    case IPPROTO_TCP:
        print_tcp(buf, n, info);
        break;
    case IPPROTO_UDP:
        print_udp(buf, n, info);
        break;
    default:
        break;
    }
}

void print_icmp(char *buf, int n, struct ip_info *info)
{
    PRINT_PROTOCOL(buf, n, "ICMP");
    switch (info->icmp.type) {
    case ICMP_ECHOREPLY:
        PRINT_INFO(buf, n, "Echo reply:   id = 0x%x  seq = %d", info->icmp.echo.id, info->icmp.echo.seq_num);
        break;
    case ICMP_ECHO:
        PRINT_INFO(buf, n, "Echo request: id = 0x%x  seq = %d", info->icmp.echo.id, info->icmp.echo.seq_num);
        break;
    case ICMP_DEST_UNREACH:
        PRINT_INFO(buf, n, "%s", get_icmp_dest_unreach_code(info->icmp.code));
        break;
    default:
        PRINT_INFO(buf, n, "Type: %d", info->icmp.type);
        break;
    }
}

void print_igmp(char *buf, int n, struct ip_info *info)
{
    PRINT_PROTOCOL(buf, n, "IGMP");
    switch (info->igmp.type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        PRINT_INFO(buf, n, "Membership query  Max response time: %d seconds",
                        info->igmp.max_resp_time / 10);
        break;
    case IGMP_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "Membership report");
        break;
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "IGMP2 Membership report");
        break;
    case IGMP_HOST_LEAVE_MESSAGE:
        PRINT_INFO(buf, n, "Leave group");
        break;
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "IGMP3 Membership report");
        break;
    default:
        PRINT_INFO(buf, n, "Type 0x%x", info->igmp.type);
        break;
    }
    PRINT_INFO(buf, n, "  Group address: %s", info->igmp.group_addr);
}

void print_tcp(char *buf, int n, struct ip_info *info)
{
    switch (info->tcp.data.utype) {
    case HTTP:
        print_http(buf, n, info->tcp.data.http);
        break;
    case DNS:
        print_dns(buf, n, info->tcp.data.dns);
        break;
    case NBNS:
        print_nbns(buf, n, info->tcp.data.nbns);
        break;
    default:
        PRINT_PROTOCOL(buf, n, "TCP");
        PRINT_INFO(buf, n, "Source port: %d  Destination port: %d", info->tcp.src_port,
                   info->tcp.dst_port);
        PRINT_INFO(buf, n, "  Flags: ");
        if (info->tcp.urg) {
            PRINT_INFO(buf, n, "URG ");
        }
        if (info->tcp.ack) {
            PRINT_INFO(buf, n, "ACK ");
        }
        if (info->tcp.psh) {
            PRINT_INFO(buf, n, "PSH ");
        }
        if (info->tcp.rst) {
            PRINT_INFO(buf, n, "RST ");
        }
        if (info->tcp.syn) {
            PRINT_INFO(buf, n, "SYN ");
        }
        if (info->tcp.fin) {
            PRINT_INFO(buf, n, "FIN");
        }
        break;
    }
}

void print_udp(char *buf, int n, struct ip_info *info)
{
    switch (info->udp.data.utype) {
    case DNS:
        print_dns(buf, n, info->udp.data.dns);
        break;
    case NBNS:
        print_nbns(buf, n, info->udp.data.nbns);
        break;
    case SSDP:
        print_ssdp(buf, n, info->udp.data.ssdp);
        break;
    default:
        PRINT_PROTOCOL(buf, n, "UDP");
        PRINT_INFO(buf, n, "Source port: %d  Destination port: %d", info->udp.src_port,
                   info->udp.dst_port);
        break;
    }
}

void print_dns(char *buf, int n, struct dns_info *dns)
{
    PRINT_PROTOCOL(buf, n, "DNS");
    if (dns->qr == 0) {
        switch (dns->opcode) {
        case DNS_QUERY:
            PRINT_INFO(buf, n, "Standard query: ");
            PRINT_INFO(buf, n, "%s ", dns->question.qname);
            PRINT_INFO(buf, n, "%s ", get_dns_class(dns->question.qclass));
            PRINT_INFO(buf, n, "%s", get_dns_type(dns->question.qtype));
            break;
        case DNS_IQUERY:
            PRINT_INFO(buf, n, "Inverse query");
            break;
        case DNS_STATUS:
            PRINT_INFO(buf, n, "Server status request");
            break;
        }
    } else {
        switch (dns->rcode) {
        case DNS_FORMAT_ERROR:
            PRINT_INFO(buf, n, "Response: format error");
            return;
        case DNS_SERVER_FAILURE:
            PRINT_INFO(buf, n, "Response: server failure");
            return;
        case DNS_NAME_ERROR:
            PRINT_INFO(buf, n, "Response: name error");
            return;
        case DNS_NOT_IMPLEMENTED:
            PRINT_INFO(buf, n, "Response: request not supported");
            return;
        case DNS_REFUSED:
            PRINT_INFO(buf, n, "Response: operation refused");
            return;
        case DNS_NO_ERROR:
        default:
            PRINT_INFO(buf, n, "Response: ");
            break;
        }
        // TODO: Need to print the proper name for all values.
        PRINT_INFO(buf, n, "%s ", dns->record[0].name);
        PRINT_INFO(buf, n, "%s ", get_dns_class(dns->record[0].class));
        PRINT_INFO(buf, n, "%s ", get_dns_type(dns->record[0].type));
        for (int i = 0; i < dns->section_count[ANCOUNT]; i++) {
            print_dns_record(dns, i, buf, n, dns->record[i].type, NULL);
            PRINT_INFO(buf, n, " ");
        }
    }
}

void print_nbns(char *buf, int n, struct nbns_info *nbns)
{
    PRINT_PROTOCOL(buf, n, "NBNS");
    if (nbns->r == 0) {
        char opcode[16];

        strncpy(opcode, get_nbns_opcode(nbns->opcode), sizeof(opcode));
        PRINT_INFO(buf, n, "Name %s request: ", strtolower(opcode));
        PRINT_INFO(buf, n, "%s ", nbns->question.qname);
        PRINT_INFO(buf, n, "%s ", get_nbns_type(nbns->question.qtype));
        if (nbns->section_count[ARCOUNT]) {
            print_nbns_record(nbns, 0, buf, n, nbns->record[0].rrtype);
        }
    } else {
        switch (nbns->rcode) {
        case NBNS_FMT_ERR:
            PRINT_INFO(buf, n, "Format Error. Request was invalidly formatted");
            return;
        case NBNS_SRV_ERR:
            PRINT_INFO(buf, n, "Server failure. Problem with NBNS, cannot process name");
            return;
        case NBNS_IMP_ERR:
            PRINT_INFO(buf, n, "Unsupported request error");
            return;
        case NBNS_RFS_ERR:
            PRINT_INFO(buf, n, "Refused error");
            return;
        case NBNS_ACT_ERR:
            PRINT_INFO(buf, n, "Active error. Name is owned by another node");
            return;
        case NBNS_CFT_ERR:
            PRINT_INFO(buf, n, "Name in conflict error");
            return;
        default:
            break;
        }
        char opcode[16];

        strncpy(opcode, get_nbns_opcode(nbns->opcode), sizeof(opcode));
        PRINT_INFO(buf, n, "Name %s response: ", strtolower(opcode));
        PRINT_INFO(buf, n, "%s ", nbns->record[0].rrname);
        PRINT_INFO(buf, n, "%s ", get_nbns_type(nbns->record[0].rrtype));
        print_nbns_record(nbns, 0, buf, n, nbns->record[0].rrtype);
    }
}

void print_ssdp(char *buf, int n, list_t *ssdp)
{
    const node_t *node;

    PRINT_PROTOCOL(buf, n, "SSDP");
    node = list_begin(ssdp);
    if (node) {
        PRINT_INFO(buf, n, (char *) list_data(node));
    }
}

void print_http(char *buf, int n, struct http_info *http)
{
    PRINT_PROTOCOL(buf, n, "HTTP");
    PRINT_INFO(buf, n, "%s", http->start_line);
}

void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type, bool *soa)
{
    switch (type) {
    case DNS_TYPE_A:
    {
        char addr[INET_ADDRSTRLEN];
        uint32_t haddr = htonl(info->record[i].rdata.address);

        inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr));
        snprintcat(buf, n, "%s", addr);
        break;
    }
    case DNS_TYPE_NS:
        snprintcat(buf, n, "%s", info->record[i].rdata.nsdname);
        break;
    case DNS_TYPE_SOA:
        if (soa) *soa = true;
        break;
    case DNS_TYPE_CNAME:
        snprintcat(buf, n, "%s", info->record[i].rdata.cname);
        break;
    case DNS_TYPE_PTR:
        snprintcat(buf, n, "%s", info->record[i].rdata.ptrdname);
        break;
    case DNS_TYPE_AAAA:
    {
        char addr[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, (struct in_addr *) info->record[i].rdata.ipv6addr, addr, sizeof(addr));
        snprintcat(buf, n, "%s", addr);
        break;
    }
    default:
        break;
    }
}

void print_nbns_record(struct nbns_info *info, int i, char *buf, int n, uint16_t type)
{
    switch (info->record[i].rrtype) {
    case NBNS_NB:
    {
        if (info->record[i].rdata.nb.g) {
            snprintcat(buf, n, "Group NetBIOS name ");
        } else {
            snprintcat(buf, n, "Unique NetBIOS name ");
        }
        int addrs = info->record[i].rdata.nb.num_addr;
        snprintcat(buf, n, "%s ", get_nbns_node_type(info->record[i].rdata.nb.ont));
        while (addrs--) {
            char addr[INET_ADDRSTRLEN];
            uint32_t haddr = htonl(info->record[i].rdata.nb.address[0]);

            inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr));
            snprintcat(buf, n, "%s ", addr);
        }
        break;
    }
    case NBNS_NS:
        snprintcat(buf, n, " NSD Name: %s", info->record[i].rdata.nsdname);
        break;
    case NBNS_A:
    {
        char addr[INET_ADDRSTRLEN];
        uint32_t haddr = htonl(info->record[i].rdata.nsdipaddr);

        inet_ntop(AF_INET, (struct in_addr *) &haddr, addr, sizeof(addr));
        snprintcat(buf, n, " NSD IP address: %s", addr);
        break;
    }
    case NBNS_NBSTAT:
        snprintcat(buf, n, "NBSTAT");
        break;
    default:
        break;
    }
}
