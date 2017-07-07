#include <arpa/inet.h>
#include <net/if_arp.h>
#include <linux/igmp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "layout.h"
#include "layout_int.h"
#include "protocols.h"
#include "../util.h"
#include "../misc.h"
#include "hexdump.h"

#define HOSTNAMELEN 255 /* maximum 255 according to rfc1035 */
#define TBUFLEN 16

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define PRINT_NUMBER(buffer, n, i)                  \
    snprintf(buffer, n, "%-" STR(NUM_WIDTH) "u", i)
#define PRINT_TIME(buffer, n, t)                    \
    snprintcat(buffer, n, "%-" STR(TIME_WIDTH) "s", t)
#define PRINT_ADDRESS(buffer, n, src, dst)                              \
    snprintcat(buffer, n, "%-" STR(ADDR_WIDTH) "s" "%-" STR(ADDR_WIDTH) "s", src, dst)
#define PRINT_PROTOCOL(buffer, n, prot)                     \
    snprintcat(buffer, n, "%-" STR(PROT_WIDTH) "s", prot)
#define PRINT_INFO(buffer, n, fmt, ...)         \
    snprintcat(buffer, n, fmt, ## __VA_ARGS__)
#define PRINT_LINE(buffer, n, i, t, src, dst, prot, fmt, ...)   \
    do {                                                        \
        PRINT_NUMBER(buffer, n, i);                             \
        PRINT_TIME(buffer, n, t);                               \
        PRINT_ADDRESS(buffer, n, src, dst);                     \
        PRINT_PROTOCOL(buffer, n, prot);                        \
        PRINT_INFO(buffer, n, fmt, ## __VA_ARGS__);             \
    } while (0)

static void print_arp(char *buf, int n, struct arp_info *info, uint32_t num, struct timeval *t);
static void print_llc(char *buf, int n, struct eth_info *eth, uint32_t num, struct timeval *t);
static void print_ip(char *buf, int n, struct ip_info *ip, uint32_t num, struct timeval *t);
static void print_ipv6(char *buf, int n, struct ipv6_info *ip, uint32_t num, struct timeval *t);
static void print_udp(char *buf, int n, struct udp_info *info);
static void print_tcp(char *buf, int n, struct tcp *info);
static void print_icmp(char *buf, int n, struct icmp_info *info);
static void print_igmp(char *buf, int n, struct igmp_info *info);
static void print_pim(char *buf, int n, struct pim_info *pim);
static void print_dns(char *buf, int n, struct dns_info *dns, uint16_t type);
static void print_nbns(char *buf, int n, struct nbns_info *nbns);
static void print_nbds(char *buf, int n, struct nbds_info *nbds);
static void print_ssdp(char *buf, int n, list_t *ssdp);
static void print_http(char *buf, int n, struct http_info *http);
static void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type);
static void print_nbns_record(struct nbns_info *info, int i, char *buf, int n, uint16_t type);
static void add_dns_soa(list_view *lw, list_view_header *w, struct dns_info *dns, int i);
static void add_dns_txt(list_view *lw, list_view_header *w, struct dns_info *dns, int i);
static void add_dns_opt(list_view *lw, list_view_header *w, struct dns_info *dns, int i);
static void add_dns_record_hdr(list_view *lw, list_view_header *header, struct dns_info *dns,
                               int idx, int max_record_name);
static void add_dns_record(list_view *lw, list_view_header *w, struct dns_info *info, int i,
                           char *buf, int n, uint16_t type);
static void add_nbns_record_hdr(list_view *lw, list_view_header *header, struct nbns_info *nbns, int i);
static void add_nbns_record(list_view *lw, list_view_header *w, struct nbns_info *nbnsn, int i,
                            char *buf, int n, uint16_t type);
static void add_tcp_options(list_view *lw, list_view_header *header, struct tcp *tcp);
static void add_pim_hello(list_view *lw, list_view_header *header, struct pim_info *pim);
static void add_pim_assert(list_view *lw, list_view_header *header, struct pim_info *pim);
static void add_pim_hello(list_view *lw, list_view_header *header, struct pim_info *pim);
static void add_pim_join_prune(list_view *lw, list_view_header *header, struct pim_info *pim);
static void add_pim_register(list_view *lw, list_view_header *header, struct pim_info *pim);
static void add_pim_register_stop(list_view *lw, list_view_header *header, struct pim_info *pim);
static void add_pim_bootstrap(list_view *lw, list_view_header *header, struct pim_info *pim);
static void add_pim_candidate(list_view *lw, list_view_header *header, struct pim_info *pim);
static void add_flags(list_view *lw, list_view_header *header, uint16_t flags, struct packet_flags *pf, int num_flags);

void write_to_buf(char *buf, int size, struct packet *p)
{
    switch (p->eth.ethertype) {
    case ETH_P_ARP:
        print_arp(buf, size, p->eth.arp, p->num, &p->time);
        break;
    case ETH_P_IP:
        print_ip(buf, size, p->eth.ip, p->num, &p->time);
        break;
    case ETH_P_IPV6:
        print_ipv6(buf, size, p->eth.ipv6, p->num, &p->time);
        break;
    default:
        if (p->eth.ethertype < ETH_P_802_3_MIN) {
            print_llc(buf, size, &p->eth, p->num, &p->time);
        } else if (p->eth.payload_len) {
            char smac[HW_ADDRSTRLEN];
            char dmac[HW_ADDRSTRLEN];
            char time[TBUFLEN];

            HW_ADDR_NTOP(smac, p->eth.mac_src);
            HW_ADDR_NTOP(dmac, p->eth.mac_dst);
            format_timeval(&p->time, time, TBUFLEN);
            PRINT_LINE(buf, size, p->num, time, smac, dmac, "ETH II", "Ethertype: 0x%x", p->eth.ethertype);
        }
        break;
    }
}

void print_arp(char *buf, int n, struct arp_info *info, uint32_t num, struct timeval *t)
{
    char sip[INET_ADDRSTRLEN];
    char tip[INET_ADDRSTRLEN];
    char sha[HW_ADDRSTRLEN];
    char time[TBUFLEN];

    inet_ntop(AF_INET, info->sip, sip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, info->tip, tip, INET_ADDRSTRLEN);
    format_timeval(t, time, TBUFLEN);
    switch (info->op) {
    case ARPOP_REQUEST:
        PRINT_LINE(buf, n, num, time, sip, tip, "ARP",
                   "Request: Looking for hardware address of %s", tip);
        break;
    case ARPOP_REPLY:
        HW_ADDR_NTOP(sha, info->sha);
        PRINT_LINE(buf, n, num, time, sip, tip, "ARP",
                   "Reply: %s has hardware address %s", sip, sha);
        break;
    default:
        PRINT_LINE(buf, n, num, time, info->sip, info->tip, "ARP", "Opcode %d", info->op);
        break;
    }
}

void print_llc(char *buf, int n, struct eth_info *eth, uint32_t num, struct timeval *t)
{
    char time[TBUFLEN];

    format_timeval(t, time, TBUFLEN);
    if (get_eth802_type(eth->llc) == ETH_802_STP) {
        char smac[HW_ADDRSTRLEN];
        char dmac[HW_ADDRSTRLEN];

        HW_ADDR_NTOP(smac, eth->mac_src);
        HW_ADDR_NTOP(dmac, eth->mac_dst);
        switch (eth->llc->bpdu->type) {
        case CONFIG:
            PRINT_LINE(buf, n, num, time, smac, dmac, "STP", "Configuration BPDU");
            break;
        case RST:
            PRINT_LINE(buf, n, num, time, smac, dmac, "STP", "Rapid Spanning Tree BPDU. Root Path Cost: %u  Port ID: 0x%x",
                       eth->llc->bpdu->root_pc, eth->llc->bpdu->port_id);
            break;
        case TCN:
            PRINT_LINE(buf, n, num, time, smac, dmac, "STP", "Topology Change Notification BPDU");
            break;
        }
    } else {
        char smac[HW_ADDRSTRLEN];
        char dmac[HW_ADDRSTRLEN];

        HW_ADDR_NTOP(smac, eth->mac_src);
        HW_ADDR_NTOP(dmac, eth->mac_dst);
        PRINT_LINE(buf, n, num, time, smac, dmac, "LLC", "SSAP: 0x%x  DSAP: 0x%x  Control: 0x%x",
                   eth->llc->ssap, eth->llc->dsap, eth->llc->control);
    }
}

void print_ip(char *buf, int n, struct ip_info *ip, uint32_t num, struct timeval *t)
{
    char time[TBUFLEN];

    format_timeval(t, time, TBUFLEN);
    PRINT_NUMBER(buf, n, num);
    PRINT_TIME(buf, n, time);
    if (!numeric && (ip->protocol != IPPROTO_UDP ||
                     (ip->protocol == IPPROTO_UDP && ip->udp.data.dns->qr == -1))) {
        char sname[HOSTNAMELEN];
        char dname[HOSTNAMELEN];

        /* get the host name of source and destination */
        gethost(ip->src, sname, HOSTNAMELEN);
        gethost(ip->dst, dname, HOSTNAMELEN);
        // TEMP: Fix this!
        sname[35] = '\0';
        dname[35] = '\0';
        PRINT_ADDRESS(buf, n, sname, dname);
    } else {
        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip->src, src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->dst, dst, INET_ADDRSTRLEN);
        PRINT_ADDRESS(buf, n, src, dst);
    }
    switch (ip->protocol) {
    case IPPROTO_ICMP:
        print_icmp(buf, n, &ip->icmp);
        break;
    case IPPROTO_IGMP:
        print_igmp(buf, n, &ip->igmp);
        break;
    case IPPROTO_TCP:
        print_tcp(buf, n, &ip->tcp);
        break;
    case IPPROTO_UDP:
        print_udp(buf, n, &ip->udp);
        break;
    case IPPROTO_PIM:
        print_pim(buf, n, &ip->pim);
        break;
    default:
    {
        char *protocol = get_ip_transport_protocol(ip->protocol);

        PRINT_PROTOCOL(buf, n, "IPv4");
        if (protocol) {
            PRINT_INFO(buf, n, "Next header: %s", protocol);
        } else {
            PRINT_INFO(buf, n, "Next header: %d", ip->protocol);
        }
        break;
    }
    }
}

void print_ipv6(char *buf, int n, struct ipv6_info *ip, uint32_t num, struct timeval *t)
{
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    char time[TBUFLEN];

    format_timeval(t, time, TBUFLEN);
    PRINT_NUMBER(buf, n, num);
    PRINT_TIME(buf, n, time);
    inet_ntop(AF_INET6, ip->src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, ip->dst, dst, INET6_ADDRSTRLEN);
    PRINT_ADDRESS(buf, n, src, dst);

    switch (ip->next_header) {
    case IPPROTO_IGMP:
        print_igmp(buf, n, &ip->igmp);
        break;
    case IPPROTO_TCP:
        print_tcp(buf, n, &ip->tcp);
        break;
    case IPPROTO_UDP:
        print_udp(buf, n, &ip->udp);
        break;
    case IPPROTO_PIM:
        print_pim(buf, n, &ip->pim);
        break;
    default:
        PRINT_PROTOCOL(buf, n, "IPv6");
        PRINT_INFO(buf, n, "Next header: %d", ip->next_header);
        break;
    }
}

void print_icmp(char *buf, int n, struct icmp_info *info)
{
    PRINT_PROTOCOL(buf, n, "ICMP");
    switch (info->type) {
    case ICMP_ECHOREPLY:
        PRINT_INFO(buf, n, "Echo reply:   id = 0x%x  seq = %d", info->echo.id, info->echo.seq_num);
        break;
    case ICMP_ECHO:
        PRINT_INFO(buf, n, "Echo request: id = 0x%x  seq = %d", info->echo.id, info->echo.seq_num);
        break;
    case ICMP_DEST_UNREACH:
        PRINT_INFO(buf, n, "%s", get_icmp_dest_unreach_code(info->code));
        break;
    default:
        PRINT_INFO(buf, n, "Type: %d", info->type);
        break;
    }
}

void print_igmp(char *buf, int n, struct igmp_info *info)
{
    char addr[INET_ADDRSTRLEN];

    PRINT_PROTOCOL(buf, n, "IGMP");
    switch (info->type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        PRINT_INFO(buf, n, "Membership query  Max response time: %d seconds",
                        info->max_resp_time / 10);
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
        PRINT_INFO(buf, n, "Type 0x%x", info->type);
        break;
    }
    inet_ntop(AF_INET, &info->group_addr, addr, INET_ADDRSTRLEN);
    PRINT_INFO(buf, n, "  Group address: %s", addr);
}

void print_pim(char *buf, int n, struct pim_info *pim)
{
    char *type = get_pim_message_type(pim->type);

    PRINT_PROTOCOL(buf, n, "PIM");
    if (type) {
        PRINT_INFO(buf, n, "Message type: %s", type);
    } else {
        PRINT_INFO(buf, n, "Message type: %d", pim->type);
    }
}

void print_tcp(char *buf, int n, struct tcp *info)
{
    switch (info->data.utype) {
    case HTTP:
        print_http(buf, n, info->data.http);
        break;
    case DNS:
    case MDNS:
        print_dns(buf, n, info->data.dns, info->data.utype);
        break;
    case NBNS:
        print_nbns(buf, n, info->data.nbns);
        break;
    default:
        PRINT_PROTOCOL(buf, n, "TCP");
        PRINT_INFO(buf, n, "Source port: %d  Destination port: %d", info->src_port,
                   info->dst_port);
        PRINT_INFO(buf, n, "  Flags: ");
        if (info->urg) {
            PRINT_INFO(buf, n, "URG ");
        }
        if (info->ack) {
            PRINT_INFO(buf, n, "ACK ");
        }
        if (info->psh) {
            PRINT_INFO(buf, n, "PSH ");
        }
        if (info->rst) {
            PRINT_INFO(buf, n, "RST ");
        }
        if (info->syn) {
            PRINT_INFO(buf, n, "SYN ");
        }
        if (info->fin) {
            PRINT_INFO(buf, n, "FIN");
        }
        break;
    }
}

void print_udp(char *buf, int n, struct udp_info *udp)
{
    switch (udp->data.utype) {
    case DNS:
    case MDNS:
        print_dns(buf, n, udp->data.dns, udp->data.utype);
        break;
    case NBNS:
        print_nbns(buf, n, udp->data.nbns);
        break;
    case NBDS:
        print_nbds(buf, n, udp->data.nbds);
        break;
    case SSDP:
        print_ssdp(buf, n, udp->data.ssdp);
        break;
    default:
        PRINT_PROTOCOL(buf, n, "UDP");
        PRINT_INFO(buf, n, "Source port: %d  Destination port: %d", udp->src_port,
                   udp->dst_port);
        break;
    }
}

void print_dns(char *buf, int n, struct dns_info *dns, uint16_t type)
{
    if (type == DNS) {
        PRINT_PROTOCOL(buf, n, "DNS");
    } else {
        PRINT_PROTOCOL(buf, n, "MDNS");
    }
    if (dns->qr == 0) {
        switch (dns->opcode) {
        case DNS_QUERY:
            PRINT_INFO(buf, n, "Standard query: ");
            PRINT_INFO(buf, n, "%s ", dns->question.qname);
            PRINT_INFO(buf, n, "%s ", get_dns_class(GET_MDNS_RRCLASS(dns->question.qclass)));
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
        PRINT_INFO(buf, n, "%s ", get_dns_class(GET_MDNS_RRCLASS(dns->record[0].rrclass)));
        PRINT_INFO(buf, n, "%s ", get_dns_type(dns->record[0].type));
        for (int i = 0; i < dns->section_count[ANCOUNT]; i++) {
            print_dns_record(dns, i, buf, n, dns->record[i].type);
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

void print_nbds(char *buf, int n, struct nbds_info *nbds)
{
    char *type;

    PRINT_PROTOCOL(buf, n, "NBDS");
    if ((type = get_nbds_message_type(nbds->msg_type))) {
        PRINT_INFO(buf, n, "%s", type);
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

void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type)
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
    case DNS_TYPE_HINFO:
        snprintcat(buf, n, "%s ", info->record[i].rdata.hinfo.cpu);
        snprintcat(buf, n, "%s", info->record[i].rdata.hinfo.os);
        break;
    case DNS_TYPE_MX:
        snprintcat(buf, n, "%u %s", info->record[i].rdata.mx.preference,
                   info->record[i].rdata.mx.exchange);
        break;
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
        break;
    default:
        break;
    }
}

void add_ethernet_information(list_view *lw, list_view_header *header, struct packet *p)
{
    char line[MAXLINE];
    char src[HW_ADDRSTRLEN];
    char dst[HW_ADDRSTRLEN];
    char *type;

    HW_ADDR_NTOP(src, p->eth.mac_src);
    HW_ADDR_NTOP(dst, p->eth.mac_dst);
    ADD_TEXT_ELEMENT(lw, header, "MAC source: %s", src);
    ADD_TEXT_ELEMENT(lw, header, "MAC destination: %s", dst);
    snprintf(line, MAXLINE, "Ethertype: 0x%x", p->eth.ethertype);
    if ((type = get_ethernet_type(p->eth.ethertype))) {
        snprintcat(line, MAXLINE, " (%s)", type);
    }
    ADD_TEXT_ELEMENT(lw, header, line);
    ADD_TEXT_ELEMENT(lw, header, "");
}

void add_llc_information(list_view *lw, list_view_header *header, struct packet *p)
{
    ADD_TEXT_ELEMENT(lw, header, "Destination Service Access Point (DSAP): 0x%x", p->eth.llc->dsap);
    ADD_TEXT_ELEMENT(lw, header, "Source Service Access Point (SSAP): 0x%x", p->eth.llc->ssap);
    ADD_TEXT_ELEMENT(lw, header, "Control: 0x%x", p->eth.llc->control);
    ADD_TEXT_ELEMENT(lw, header, "");
}

void add_snap_information(list_view *lw, list_view_header *header, struct packet *p)
{
    ADD_TEXT_ELEMENT(lw, header, "IEEE Organizationally Unique Identifier (OUI): 0x%06x\n",
              get_eth802_oui(p->eth.llc->snap));
    ADD_TEXT_ELEMENT(lw, header, "Protocol Id: 0x%04x\n", p->eth.llc->snap->protocol_id);
    ADD_TEXT_ELEMENT(lw, header, "");
}

void add_arp_information(list_view *lw, list_view_header *header, struct packet *p)
{
    char sip[INET_ADDRSTRLEN];
    char tip[INET_ADDRSTRLEN];
    char sha[HW_ADDRSTRLEN];
    char tha[HW_ADDRSTRLEN];

    HW_ADDR_NTOP(sha, p->eth.arp->sha);
    HW_ADDR_NTOP(tha, p->eth.arp->tha);
    inet_ntop(AF_INET, p->eth.arp->sip, sip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, p->eth.arp->tip, tip, INET_ADDRSTRLEN);
    ADD_TEXT_ELEMENT(lw, header, "Hardware type: %d (%s)", p->eth.arp->ht, get_arp_hardware_type(p->eth.arp->ht));
    ADD_TEXT_ELEMENT(lw, header, "Protocol type: 0x%x (%s)", p->eth.arp->pt, get_arp_protocol_type(p->eth.arp->pt));
    ADD_TEXT_ELEMENT(lw, header, "Hardware size: %d", p->eth.arp->hs);
    ADD_TEXT_ELEMENT(lw, header, "Protocol size: %d", p->eth.arp->ps);
    ADD_TEXT_ELEMENT(lw, header, "Opcode: %d (%s)", p->eth.arp->op, get_arp_opcode(p->eth.arp->op));
    ADD_TEXT_ELEMENT(lw, header, "");
    ADD_TEXT_ELEMENT(lw, header, "Sender IP: %-15s  HW: %s", sip, sha);
    ADD_TEXT_ELEMENT(lw, header, "Target IP: %-15s  HW: %s", tip, tha);
}

void add_stp_information(list_view *lw, list_view_header *header, struct packet *p)
{
    uint16_t flags;
    struct stp_info *stp;
    list_view_header *hdr;

    stp = p->eth.llc->bpdu;
    flags = stp->tcack << 7 | stp->agreement << 6 | stp->forwarding << 5 | stp->forwarding << 4 |
        stp->port_role << 2 | stp->proposal << 1 | stp->tc;
    ADD_TEXT_ELEMENT(lw, header, "Protocol Id: %d", stp->protocol_id);
    ADD_TEXT_ELEMENT(lw, header, "Version: %d", stp->version);
    ADD_TEXT_ELEMENT(lw, header, "Type: %d (%s)", stp->type, get_stp_bpdu_type(stp->type));
    if (stp->type == CONFIG || stp->type == RST) {
        char buf[1024];

        memset(buf, 0, 1024);
        snprintcat(buf, 1024, "Flags: ");
        if (stp->tcack) snprintcat(buf, 1024, "Topology Change Ack, ");
        if (stp->agreement) snprintcat(buf, 1024, "Agreement, ");
        if (stp->forwarding) snprintcat(buf, 1024, "Forwarding, ");
        if (stp->learning) snprintcat(buf, 1024, "Learning, ");
        if (stp->proposal) snprintcat(buf, 1024, "Proposal, ");
        if (stp->tc) snprintcat(buf, 1024, "Topology Change, ");
        if (stp->port_role) {
            snprintcat(buf, 1024, "Port Role: ");
            if (stp->port_role == 0x01) snprintcat(buf, 1024, "Backup");
            if (stp->port_role == 0x02) snprintcat(buf, 1024, "Root");
            if (stp->port_role == 0x03) snprintcat(buf, 1024, "Designated");
        }
        hdr = ADD_SUB_HEADER(lw, header, selected[STP_FLAGS], STP_FLAGS, "%s (0x%x)", buf, flags);
        add_flags(lw, hdr, flags, get_stp_flags(), 7);
        ADD_TEXT_ELEMENT(lw, header, "Root ID: %u/%02x.%02x.%02x.%02x.%02x.%02x", stp->root_id[0] << 8 |
                  stp->root_id[1], stp->root_id[2], stp->root_id[3],
                  stp->root_id[4], stp->root_id[5], stp->root_id[6],
                  stp->root_id[7]);
        ADD_TEXT_ELEMENT(lw, header, "Root Path Cost: %d", stp->root_pc);
        ADD_TEXT_ELEMENT(lw, header, "Bridge ID: %u/%02x.%02x.%02x.%02x.%02x.%02x", stp->bridge_id[0] << 8 |
                  stp->bridge_id[1], stp->bridge_id[2], stp->bridge_id[3],
                  stp->bridge_id[4], stp->bridge_id[5], stp->bridge_id[6],
                  stp->bridge_id[7]);
        ADD_TEXT_ELEMENT(lw, header, "Port ID: 0x%x", stp->port_id);
        ADD_TEXT_ELEMENT(lw, header, "Message Age: %u s.", stp->msg_age / 256);
        ADD_TEXT_ELEMENT(lw, header, "Max Age: %u s.", stp->max_age / 256);
        ADD_TEXT_ELEMENT(lw, header, "Hello Time: %u s.", stp->ht / 256);
        ADD_TEXT_ELEMENT(lw, header, "Forward Delay: %u s.", stp->fd / 256);
    }
}

void add_ipv4_information(list_view *lw, list_view_header *header, struct ip_info *ip)
{
    char *protocol;
    char *dscp;
    char buf[MAXLINE];
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    list_view_header *hdr;
    uint8_t flags;

    flags = (ip->foffset & 0x8000) >> 13 | (ip->foffset & 0x4000) >> 13 |
        (ip->foffset & 0x2000) >> 13;
    ADD_TEXT_ELEMENT(lw, header, "Version: %u", ip->version);
    ADD_TEXT_ELEMENT(lw, header, "Internet Header Length (IHL): %u", ip->ihl);
    snprintf(buf, MAXLINE, "Differentiated Services Code Point (DSCP): 0x%x", ip->dscp);
    if ((dscp = get_ip_dscp(ip->dscp))) {
        snprintcat(buf, MAXLINE, " %s", dscp);
    }
    ADD_TEXT_ELEMENT(lw, header, "%s", buf);
    snprintf(buf, MAXLINE, "Explicit Congestion Notification (ECN): 0x%x", ip->ecn);
    if (ip->ecn & 0x3) {
        snprintcat(buf, MAXLINE, " CE");
    } else if (ip->ecn & 0x1) {
        snprintcat(buf, MAXLINE, " ECT(1)");
    } else if (ip->ecn & 0x2) {
        snprintcat(buf, MAXLINE, " ECT(0)");
    } else {
        snprintcat(buf, MAXLINE, " Not ECN-Capable");
    }
    ADD_TEXT_ELEMENT(lw, header, "Total length: %u", ip->length);
    ADD_TEXT_ELEMENT(lw, header, "Identification: 0x%x (%u)", ip->id, ip->id);
    snprintf(buf, MAXLINE, "Flags 0x%x ", flags);
    if (ip->foffset & 0x4000 || ip->foffset & 0x2000) {
        snprintcat(buf, MAXLINE, "(");
        if (ip->foffset & 0x4000) snprintcat(buf, MAXLINE, "Don't Fragment");
        if (ip->foffset & 0x2000) snprintcat(buf, MAXLINE, "More Fragments");
        snprintcat(buf, MAXLINE, ")");
    }
    hdr = ADD_SUB_HEADER(lw, header, selected[IPV4_FLAGS], IPV4_FLAGS, "%s", buf, flags);
    add_flags(lw, hdr, flags, get_ipv4_flags(), 3);
    ADD_TEXT_ELEMENT(lw, header, "Fragment offset: %u", get_ipv4_foffset(ip));
    ADD_TEXT_ELEMENT(lw, header, "Time to live: %u", ip->ttl);
    snprintf(buf, MAXLINE, "Protocol: %u", ip->protocol);
    if ((protocol = get_ip_transport_protocol(ip->protocol))) {
        snprintcat(buf, MAXLINE, " (%s)", protocol);
    }
    ADD_TEXT_ELEMENT(lw, header, "%s", buf);
    ADD_TEXT_ELEMENT(lw, header,"Checksum: %u", ip->checksum);
    inet_ntop(AF_INET, &ip->src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->dst, dst, INET_ADDRSTRLEN);
    ADD_TEXT_ELEMENT(lw, header,"Source IP address: %s", src);
    ADD_TEXT_ELEMENT(lw, header,"Destination IP address: %s", dst);
    ADD_TEXT_ELEMENT(lw, header, "");
}

void add_ipv6_information(list_view *lw, list_view_header *header, struct ipv6_info *ip)
{
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    char *protocol;
    char buf[MAXLINE];

    inet_ntop(AF_INET6, ip->src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, ip->dst, dst, INET6_ADDRSTRLEN);
    ADD_TEXT_ELEMENT(lw, header, "Version: %u", ip->version);
    ADD_TEXT_ELEMENT(lw, header, "Traffic class: 0x%x", ip->tc);
    ADD_TEXT_ELEMENT(lw, header, "Flow label: 0x%x", ip->flow_label);
    ADD_TEXT_ELEMENT(lw, header, "Payload length: %u", ip->payload_len);
    snprintf(buf, MAXLINE, "Next header: %u", ip->next_header);
    if ((protocol = get_ip_transport_protocol(ip->next_header))) {
        snprintcat(buf, MAXLINE, " (%s)", protocol);
    }
    ADD_TEXT_ELEMENT(lw, header, "%s", buf);
    ADD_TEXT_ELEMENT(lw, header, "Hop limit: %u", ip->hop_limit);
    ADD_TEXT_ELEMENT(lw, header, "Source address: %s", src);
    ADD_TEXT_ELEMENT(lw, header, "Destination address: %s", dst);
    ADD_TEXT_ELEMENT(lw, header, "");
}

void add_icmp_information(list_view *lw, list_view_header *header, struct icmp_info *icmp)
{
    ADD_TEXT_ELEMENT(lw, header, "Type: %d (%s)", icmp->type, get_icmp_type(icmp->type));
    switch (icmp->type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp->code);
        break;
    case ICMP_DEST_UNREACH:
        ADD_TEXT_ELEMENT(lw, header, "Code: %d (%s)", icmp->code, get_icmp_dest_unreach_code(icmp->code));
        break;
    default:
        break;
    }
    ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
    if (icmp->type == ICMP_ECHOREPLY || icmp->type == ICMP_ECHO) {
        ADD_TEXT_ELEMENT(lw, header, "Identifier: 0x%x", icmp->echo.id);
        ADD_TEXT_ELEMENT(lw, header, "Sequence number: %d", icmp->echo.seq_num);
    }
}

void add_igmp_information(list_view *lw, list_view_header *header, struct igmp_info *igmp)
{
    char addr[INET_ADDRSTRLEN];
    char buf[MAXLINE];
    char *type;

    inet_ntop(AF_INET, &igmp->group_addr, addr, INET_ADDRSTRLEN);
    snprintf(buf, MAXLINE, "Type: %d", igmp->type);
    if ((type = get_igmp_type(igmp->type))) {
        snprintcat(buf, MAXLINE, " (%s)", type);
    }
    ADD_TEXT_ELEMENT(lw, header, "%s", buf);
    if (igmp->type == IGMP_HOST_MEMBERSHIP_QUERY) {
        if (!strcmp(addr, "0.0.0.0")) {
            ADD_TEXT_ELEMENT(lw, header, "General query");
        } else {
            ADD_TEXT_ELEMENT(lw, header, "Group-specific query");
        }
    }
    ADD_TEXT_ELEMENT(lw, header, "Max response time: %d seconds", igmp->max_resp_time / 10);
    ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", igmp->checksum);
    ADD_TEXT_ELEMENT(lw, header, "Group address: %s", addr);
}

void add_pim_information(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    char *type = get_pim_message_type(pim->type);

    ADD_TEXT_ELEMENT(lw, header, "Version: %d", pim->version);
    if (type) {
        ADD_TEXT_ELEMENT(lw, header, "Type: %d (%s)", pim->type, type);
    } else {
        ADD_TEXT_ELEMENT(lw, header, "Type: %d", pim->type);
    }
    ADD_TEXT_ELEMENT(lw, header, "Checksum: %u", pim->checksum);
    switch (pim->type) {
    case PIM_HELLO:
        add_pim_hello(lw, header, pim);
        break;
    case PIM_REGISTER:
        add_pim_register(lw, header, pim);
        break;
    case PIM_REGISTER_STOP:
        add_pim_register_stop(lw, header, pim);
        break;
    case PIM_ASSERT:
        add_pim_assert(lw, header, pim);
        break;
    case PIM_JOIN_PRUNE:
    case PIM_GRAFT:
    case PIM_GRAFT_ACK:
        add_pim_join_prune(lw, header, pim);
        break;
    case PIM_BOOTSTRAP:
        add_pim_bootstrap(lw, header, pim);
        break;
    case PIM_CANDIDATE_RP_ADVERTISEMENT:
        add_pim_candidate(lw, header, pim);
        break;
    default:
        break;
    }
}

void add_pim_hello(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_t *opt;
    const node_t *n;
    list_view_header *h;

    opt = parse_hello_options(pim);
    h = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Hello Message (%d options)", list_size(opt));
    n = list_begin(opt);
    while (n) {
        struct pim_hello *hello = list_data(n);
        list_view_header *w;
        struct tm_t tm;
        char time[512];

        switch (hello->option_type) {
        case PIM_HOLDTIME:
            tm = get_time(hello->holdtime);
            time_ntop(&tm, time, 512);
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Holdtime: %s", time);
            ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        case PIM_LAN_PRUNE_DELAY:
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "LAN Prune Delay");
            ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            ADD_TEXT_ELEMENT(lw, w, "Propagation delay: %u ms", hello->lan_prune_delay.prop_delay);
            ADD_TEXT_ELEMENT(lw, w, "Override interval: %u ms", hello->lan_prune_delay.override_interval);
            break;
        case PIM_DR_PRIORITY:
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "DR Priority: %u", hello->dr_priority);
            ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        case PIM_GENERATION_ID:
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Generation ID: %u", hello->gen_id);
            ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        case PIM_STATE_REFRESH_CAPABLE:
            memset(&time, 0, 512);
            tm = get_time(hello->state_refresh.interval);
            time_ntop(&tm, time, 512);
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "State Refresh Capable");
            ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            ADD_TEXT_ELEMENT(lw, w, "Version: %u", hello->state_refresh.version);
            ADD_TEXT_ELEMENT(lw, w, "Interval: %s", time);
            break;
        case PIM_ADDRESS_LIST:
        default:
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Unknown option: %u", hello->option_type);
            ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        }
        n = list_next(n);
        if (n) ADD_TEXT_ELEMENT(lw, w, "");
    }
    list_free(opt, free);
}

void add_pim_register(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Register Message");

    ADD_TEXT_ELEMENT(lw, h, "Border bit: %d", pim->reg->border);
    ADD_TEXT_ELEMENT(lw, h, "Null-Register bit: %d", pim->reg->null);
    if (pim->reg->data) {
        list_view_header *w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Data");

        add_hexdump(lw, w, HEXMODE_NORMAL, pim->reg->data, pim->reg->data_len);
    }
}

void add_pim_register_stop(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h;
    char *addr;

    h = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Register-Stop Message");
    addr = get_pim_address(pim->assert->gaddr.addr_family, pim->assert->gaddr.addr);
    if (addr) {
        ADD_TEXT_ELEMENT(lw, h, "Group address: %s/%d", addr, pim->assert->gaddr.mask_len);
        free(addr);
    }
    addr = get_pim_address(pim->assert->saddr.addr_family, pim->assert->saddr.addr);
    if (addr) {
        ADD_TEXT_ELEMENT(lw, h, "Source address: %s", addr);
        free(addr);
    }
}

void add_pim_assert(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h;
    char *addr;

    h = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Assert Message");
    addr = get_pim_address(pim->assert->gaddr.addr_family, pim->assert->gaddr.addr);
    if (addr) {
        ADD_TEXT_ELEMENT(lw, h, "Group address: %s/%d", addr, pim->assert->gaddr.mask_len);
        free(addr);
    }
    addr = get_pim_address(pim->assert->saddr.addr_family, pim->assert->saddr.addr);
    if (addr) {
        ADD_TEXT_ELEMENT(lw, h, "Source address: %s", addr);
        free(addr);
    }
    ADD_TEXT_ELEMENT(lw, h, "RPTbit: %u", GET_RPTBIT(pim->assert->metric_pref));
    ADD_TEXT_ELEMENT(lw, h, "Metric preference: %u", GET_METRIC_PREFERENCE(pim->assert->metric_pref));
    ADD_TEXT_ELEMENT(lw, h, "Metric: %u", pim->assert->metric);
}

void add_pim_join_prune(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h;
    list_view_header *grp;
    char *addr;
    struct tm_t tm;
    char time[512];

    switch (pim->type) {
    case PIM_JOIN_PRUNE:
        h = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Join/Prune Message");
        break;
    case PIM_GRAFT:
        h = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Graft Message");
        break;
    case PIM_GRAFT_ACK:
        h = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Graft Ack Message");
        break;
    default:
        return;
    }

    addr = get_pim_address(pim->jpg->neighbour.addr_family, pim->jpg->neighbour.addr);
    if (addr) {
        ADD_TEXT_ELEMENT(lw, h, "Upstream neighbour: %s", addr);
        free(addr);
    }
    tm = get_time(pim->jpg->holdtime);
    time_ntop(&tm, time, 512);
    ADD_TEXT_ELEMENT(lw, h, "Holdtime: %s", time);

    grp = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Groups (%d)", pim->jpg->num_groups);

    for (int i = 0; i < pim->jpg->num_groups; i++) {
        list_view_header *joined;
        list_view_header *pruned;

        addr = get_pim_address(pim->jpg->groups[i].gaddr.addr_family, pim->jpg->groups[i].gaddr.addr);
        if (addr) {
            ADD_TEXT_ELEMENT(lw, grp, "Group address %d: %s/%d", i + 1, addr, pim->jpg->groups[i].gaddr.mask_len);
            free(addr);
        }

        joined = ADD_SUB_HEADER(lw, grp, false, SUBLAYER, "Joined sources (%d)",
                                pim->jpg->groups[i].num_joined_src);
        for (int j = 0; j < pim->jpg->groups[i].num_joined_src; j++) {
            addr = get_pim_address(pim->jpg->groups[i].joined_src[j].addr_family,
                                   pim->jpg->groups[i].joined_src[j].addr);
            if (addr) {
                ADD_TEXT_ELEMENT(lw, joined, "Joined address %d: %s/%d", j + 1, addr,
                                 pim->jpg->groups[i].joined_src[j].mask_len);
                free(addr);
            }
        }
        ADD_TEXT_ELEMENT(lw, joined, "");

        pruned = ADD_SUB_HEADER(lw, grp, false, SUBLAYER, "Pruned sources (%d)",
                                pim->jpg->groups[i].num_pruned_src);
        for (int j = 0; j < pim->jpg->groups[i].num_pruned_src; j++) {
            addr = get_pim_address(pim->jpg->groups[i].pruned_src[j].addr_family,
                                   pim->jpg->groups[i].pruned_src[j].addr);
            if (addr) {
                ADD_TEXT_ELEMENT(lw, pruned, "Pruned address %d: %s/%d", j + 1, addr,
                                 pim->jpg->groups[i].pruned_src[j].mask_len);
                free(addr);
            }
        }
    }
}

void add_pim_bootstrap(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h;
    list_view_header *grp;
    char *addr;

    h = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Bootstrap Message");
    ADD_TEXT_ELEMENT(lw, h, "Fragment tag: 0x%x", pim->bootstrap->tag);
    ADD_TEXT_ELEMENT(lw, h, "Hash mask length: %d", pim->bootstrap->hash_len);
    ADD_TEXT_ELEMENT(lw, h, "BSR priority: %d", pim->bootstrap->priority);
    addr = get_pim_address(pim->bootstrap->bsr_addr.addr_family, pim->bootstrap->bsr_addr.addr);
    if (addr) {
        ADD_TEXT_ELEMENT(lw, h, "BSR address: %s", addr);
        free(addr);
    }
    addr = get_pim_address(pim->bootstrap->groups->gaddr.addr_family, pim->bootstrap->groups->gaddr.addr);
    if (addr) {
        grp = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Group %s/%d", addr, pim->bootstrap->groups->gaddr.mask_len);
        free(addr);
    }
    ADD_TEXT_ELEMENT(lw, grp, "RP count: %u", pim->bootstrap->groups->rp_count);
    ADD_TEXT_ELEMENT(lw, grp, "Frag RP count: %u", pim->bootstrap->groups->frag_rp_count);
    for (int i = 0; i < pim->bootstrap->groups->frag_rp_count; i++) {
        addr = get_pim_address(pim->bootstrap->groups->rps[i].rp_addr.addr_family,
                               pim->bootstrap->groups->rps[i].rp_addr.addr);
        if (addr) {
            ADD_TEXT_ELEMENT(lw, grp, "RP address %d: %s", i, addr);
            free(addr);
        }
        ADD_TEXT_ELEMENT(lw, grp, "Holdtime: %u", pim->bootstrap->groups->rps[i].holdtime);
        ADD_TEXT_ELEMENT(lw, grp, "Priority: %u", pim->bootstrap->groups->rps[i].priority);
    }
}

void add_pim_candidate(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h;
    char *addr;

    h = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Candidate-RP-Advertisement Message");
    ADD_TEXT_ELEMENT(lw, h, "Prefix count: %u", pim->candidate->prefix_count);
    ADD_TEXT_ELEMENT(lw, h, "Priority: %u", pim->candidate->priority);
    ADD_TEXT_ELEMENT(lw, h, "Holdtime: %u", pim->candidate->holdtime);
    addr = get_pim_address(pim->candidate->rp_addr.addr_family, pim->candidate->rp_addr.addr);
    if (addr) {
        ADD_TEXT_ELEMENT(lw, h, "RP address: %s", addr);
        free(addr);
    }
    for (int i = 0; i < pim->candidate->prefix_count; i++) {
        addr = get_pim_address(pim->candidate->gaddrs[i].addr_family, pim->candidate->gaddrs[i].addr);
        if (addr) {
            ADD_TEXT_ELEMENT(lw, h, "Group address %d: %s/%d", i, addr, pim->candidate->gaddrs[i].mask_len);
            free(addr);
        }
    }
}

void add_udp_information(list_view *lw, list_view_header *header, struct udp_info *udp)
{
    ADD_TEXT_ELEMENT(lw, header, "Source port: %u", udp->src_port);
    ADD_TEXT_ELEMENT(lw, header, "Destination port: %u", udp->dst_port);
    ADD_TEXT_ELEMENT(lw, header, "Length: %u", udp->len);
    ADD_TEXT_ELEMENT(lw, header, "Checksum: %u", udp->checksum);
    ADD_TEXT_ELEMENT(lw, header, "");
}

void add_tcp_information(list_view *lw, list_view_header *header, struct tcp *tcp)
{
    int n = 32;
    char buf[n];
    list_view_header *hdr;
    uint16_t flags;

    flags = (uint16_t) (tcp->ns << 8 | tcp->cwr << 7 | tcp->ece << 6 | tcp->urg << 5 |
                        tcp->ack << 4 | tcp->psh << 3 | tcp->rst << 2 | tcp->syn << 1 |
                        tcp->fin);
    memset(buf, 0, n);
    if (tcp->urg) {
        snprintcat(buf, n, "URG ");
    }
    if (tcp->ack) {
        snprintcat(buf, n, "ACK ");
    }
    if (tcp->psh) {
        snprintcat(buf, n, "PSH ");
    }
    if (tcp->rst) {
        snprintcat(buf, n, "RST ");
    }
    if (tcp->syn) {
        snprintcat(buf, n, "SYN ");
    }
    if (tcp->fin) {
        snprintcat(buf, n, "FIN ");
    }
    ADD_TEXT_ELEMENT(lw, header, "Source port: %u", tcp->src_port);
    ADD_TEXT_ELEMENT(lw, header, "Destination port: %u", tcp->dst_port);
    ADD_TEXT_ELEMENT(lw, header, "Sequence number: %u", tcp->seq_num);
    ADD_TEXT_ELEMENT(lw, header, "Acknowledgment number: %u", tcp->ack_num);
    ADD_TEXT_ELEMENT(lw, header, "Data offset: %u", tcp->offset);
    hdr = ADD_SUB_HEADER(lw, header, selected[TCP_FLAGS], TCP_FLAGS, "Flags: %s(0x%x)", buf, flags);
    add_flags(lw, hdr, flags, get_tcp_flags(), 9);
    ADD_TEXT_ELEMENT(lw, header, "Window size: %u", tcp->window);
    ADD_TEXT_ELEMENT(lw, header, "Checksum: %u", tcp->checksum);
    ADD_TEXT_ELEMENT(lw, header, "Urgent pointer: %u", tcp->urg_ptr);
    if (tcp->options) {
        add_tcp_options(lw, header, tcp);
    }
    ADD_TEXT_ELEMENT(lw, header, "");
}

void add_tcp_options(list_view *lw, list_view_header *header, struct tcp *tcp)
{
    list_t *options;
    const node_t *n;
    list_view_header *h;

    options = parse_tcp_options(tcp->options, (tcp->offset - 5) * 4);
    h = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Options");
    n = list_begin(options);

    while (n) {
        struct tcp_options *opt = list_data(n);
        list_view_header *w;

        switch (opt->option_kind) {
        case TCP_OPT_NOP:
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "No operation");
            ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_MSS:
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Maximum segment size: %u", opt->mss);
            ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_WIN_SCALE:
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Window scale: %u", opt->win_scale);
            ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_SAP:
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Selective Acknowledgement permitted");
            ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_SACK:
        {
            const node_t *n = list_begin(opt->sack);

            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Selective Acknowledgement");
            ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            while (n) {
                struct tcp_sack_block *block = list_data(n);

                ADD_TEXT_ELEMENT(lw, w, "Left edge: %u", block->left_edge);
                ADD_TEXT_ELEMENT(lw, w, "Right edge: %u", block->right_edge);
                n = list_next(n);
            }
            break;
        }
        case TCP_OPT_TIMESTAMP:
            w = ADD_SUB_HEADER(lw, h, false, SUBLAYER, "Timestamp");
            ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            ADD_TEXT_ELEMENT(lw, w, "Timestamp value: %u", opt->ts_val);
            ADD_TEXT_ELEMENT(lw, w, "Timestamp echo reply: %u", opt->ts_ecr);
            break;
        default:
            break;
        }
        n = list_next(n);
        if (n) ADD_TEXT_ELEMENT(lw, w, "");
    }
    free_tcp_options(options);
}

void add_dns_information(list_view *lw, list_view_header *header, struct dns_info *dns)
{
    int records = 0;
    int answers = dns->section_count[ANCOUNT];
    int authority = dns->section_count[NSCOUNT];
    int additional = dns->section_count[ARCOUNT];
    list_view_header *hdr;
    uint16_t flags;

    flags = dns->aa << 6 | dns->tc << 5 | dns->rd << 4 | dns->ra << 3;

    /* number of resource records */
    for (int i = 1; i < 4; i++) {
        records += dns->section_count[i];
    }
    ADD_TEXT_ELEMENT(lw, header, "ID: 0x%x", dns->id);
    ADD_TEXT_ELEMENT(lw, header, "QR: %d (%s)", dns->qr, dns->qr ? "DNS Response" : "DNS Query");
    ADD_TEXT_ELEMENT(lw, header, "Opcode: %d (%s)", dns->opcode, get_dns_opcode(dns->opcode));

    hdr = ADD_SUB_HEADER(lw, header, selected[DNS_FLAGS], DNS_FLAGS, "Flags 0x%x", flags);
    add_flags(lw, hdr, flags, get_dns_flags(), 5);
    if (dns->qr) {
        ADD_TEXT_ELEMENT(lw, header, "Rcode: %d (%s)", dns->rcode, get_dns_rcode(dns->rcode));
    }
    ADD_TEXT_ELEMENT(lw, header, "Question: %d, Answer: %d, Authority: %d, Additional records: %d",
                     dns->section_count[QDCOUNT], answers, authority, additional);
    if (dns->section_count[QDCOUNT]) {
        list_view_header *hdr;

        hdr = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Questions");
        for (int i = dns->section_count[QDCOUNT]; i > 0; i--) {
            ADD_TEXT_ELEMENT(lw, hdr, "QNAME: %s, QTYPE: %s, QCLASS: %s",
                             dns->question.qname, get_dns_type_extended(dns->question.qtype),
                             get_dns_class_extended(GET_MDNS_RRCLASS(dns->question.qclass)));
            if (records) {
                ADD_TEXT_ELEMENT(lw, hdr, "");
            }
        }
    }
    if (records) {
        int len;
        list_view_header *hdr = NULL;

        if (answers) {
            len = get_dns_max_namelen(dns->record, answers);
            hdr = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Answers");
            for (int i = 0; i < answers; i++) {
                add_dns_record_hdr(lw, hdr, dns, i, len);
            }
        }
        if (authority) {
            if (hdr) ADD_TEXT_ELEMENT(lw, hdr, "");
            len = get_dns_max_namelen(dns->record + answers, authority);
            hdr = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Authoritative nameservers");
            for (int i = 0; i < authority; i++) {
                add_dns_record_hdr(lw, hdr, dns, i + answers, len);
            }
        }
        if (additional) {
            if (hdr) ADD_TEXT_ELEMENT(lw, hdr, "");
            len = get_dns_max_namelen(dns->record + answers + authority, additional);
            hdr = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Additional records");
            for (int i = 0; i < additional; i++) {
                add_dns_record_hdr(lw, hdr, dns, i + answers + authority, len);
            }
        }
    }
}

void add_dns_record_hdr(list_view *lw, list_view_header *header, struct dns_info *dns,
                        int idx, int max_record_name)
{
    char buffer[MAXLINE];
    list_view_header *w;

    /* the OPT resource record has special handling of the fixed parts of the record */
    if (dns->record[idx].type == DNS_TYPE_OPT) {
        if (!dns->record[idx].name[0]) { /* the name must be 0 (root domain) */
            char *name = "<root domain>";

            if (max_record_name == 0) {
                snprintf(buffer, MAXLINE, "%-*s", (int ) strlen(name) + 4, name);
            } else {
                snprintf(buffer, MAXLINE, "%-*s", max_record_name + 4, name);
            }
        } else {
            snprintf(buffer, MAXLINE, "%-*s", max_record_name + 4, dns->record[idx].name);
        }
        /* class is the requestor's UDP payload size*/
        snprintcat(buffer, MAXLINE, "%-6d", GET_MDNS_RRCLASS(dns->record[idx].rrclass));
    } else {
        snprintf(buffer, MAXLINE, "%-*s", max_record_name + 4, dns->record[idx].name);
        snprintcat(buffer, MAXLINE, "%-6s", get_dns_class(GET_MDNS_RRCLASS(dns->record[idx].rrclass)));
    }
    snprintcat(buffer, MAXLINE, "%-8s", get_dns_type(dns->record[idx].type));
    print_dns_record(dns, idx, buffer, MAXLINE, dns->record[idx].type);
    w = ADD_SUB_HEADER(lw, header, false, SUBLAYER, "%s", buffer);
    add_dns_record(lw, w, dns, idx, buffer, MAXLINE, dns->record[idx].type);
}

void add_dns_record(list_view *lw, list_view_header *w, struct dns_info *dns, int i, char *buf, int n, uint16_t type)
{
    char time[512];
    struct tm_t tm;

    if (dns->record[i].type != DNS_TYPE_OPT) {
        ADD_TEXT_ELEMENT(lw, w, "Name: %s", dns->record[i].name);
        ADD_TEXT_ELEMENT(lw, w, "Type: %s", get_dns_type_extended(dns->record[i].type));
        ADD_TEXT_ELEMENT(lw, w, "Class: %s", get_dns_class_extended(GET_MDNS_RRCLASS(dns->record[i].rrclass)));
        tm = get_time(dns->record[i].ttl);
        time_ntop(&tm, time, 512);
        ADD_TEXT_ELEMENT(lw, w, "TTL: %s", time);
    }

    switch (type) {
    case DNS_TYPE_SOA:
        add_dns_soa(lw, w, dns, i);
        break;
    case DNS_TYPE_MX:
        ADD_TEXT_ELEMENT(lw, w, "Preference: %u", dns->record[i].rdata.mx.preference);
        ADD_TEXT_ELEMENT(lw, w, "Mail exchange: %s", dns->record[i].rdata.mx.exchange);
        break;
    case DNS_TYPE_SRV:
        ADD_TEXT_ELEMENT(lw, w, "Priority: %u", dns->record[i].rdata.srv.priority);
        ADD_TEXT_ELEMENT(lw, w, "Weight: %u", dns->record[i].rdata.srv.weight);
        ADD_TEXT_ELEMENT(lw, w, "Port: %u", dns->record[i].rdata.srv.port);
        ADD_TEXT_ELEMENT(lw, w, "Target: %s", dns->record[i].rdata.srv.target);
        break;
    case DNS_TYPE_TXT:
        add_dns_txt(lw, w, dns, i);
        break;
    case DNS_TYPE_OPT:
        add_dns_opt(lw, w, dns, i);
        break;
    default:
        break;
    }
    ADD_TEXT_ELEMENT(lw, w, "");
}

void add_dns_txt(list_view *lw, list_view_header *w, struct dns_info *dns, int i)
{
    const node_t *node = list_begin(dns->record[i].rdata.txt);

    while (node) {
        struct dns_txt_rr *rr = (struct dns_txt_rr *) list_data(node);

        ADD_TEXT_ELEMENT(lw, w, "TXT: %s", (rr->txt == NULL) ? "" : rr->txt);
        ADD_TEXT_ELEMENT(lw, w, "TXT length: %d", rr->len);
        node = list_next(node);
    }
}

void add_dns_soa(list_view *lw, list_view_header *w, struct dns_info *dns, int i)
{
    char time[512];
    struct tm_t tm;

    ADD_TEXT_ELEMENT(lw, w, "mname (primary name server): %s", dns->record[i].rdata.soa.mname);
    ADD_TEXT_ELEMENT(lw, w, "rname (mailbox of responsible authority): %s",
              dns->record[i].rdata.soa.rname);
    ADD_TEXT_ELEMENT(lw, w, "Serial number: %u", dns->record[i].rdata.soa.serial);
    tm = get_time(dns->record[i].rdata.soa.refresh);
    time_ntop(&tm, time, 512);
    ADD_TEXT_ELEMENT(lw, w, "Refresh interval: %d (%s)",
              dns->record[i].rdata.soa.refresh, time);
    tm = get_time(dns->record[i].rdata.soa.retry);
    time_ntop(&tm, time, 512);
    ADD_TEXT_ELEMENT(lw, w, "Retry interval: %d (%s)",
              dns->record[i].rdata.soa.retry, time);
    tm = get_time(dns->record[i].rdata.soa.expire);
    time_ntop(&tm, time, 512);
    ADD_TEXT_ELEMENT(lw, w, "Expire limit: %d (%s)",
              dns->record[i].rdata.soa.expire, time);
    tm = get_time(dns->record[i].rdata.soa.minimum);
    time_ntop(&tm, time, 512);
    ADD_TEXT_ELEMENT(lw, w,  "Minimum TTL: %d (%s)",
              dns->record[i].rdata.soa.minimum, time);
}

void add_dns_opt(list_view *lw, list_view_header *w, struct dns_info *dns, int i)
{
    list_t *opt;
    const node_t *n;

    if (!dns->record[i].name[0]) {
        ADD_TEXT_ELEMENT(lw, w, "Name: <root domain>");
    } else {
        ADD_TEXT_ELEMENT(lw, w, "Name: %s", dns->record[i].name);
    }
    ADD_TEXT_ELEMENT(lw, w, "Type: %s", get_dns_type_extended(dns->record[i].type));
    ADD_TEXT_ELEMENT(lw, w, "UDP payload size: %u", GET_MDNS_RRCLASS(dns->record[i].rrclass));
    ADD_TEXT_ELEMENT(lw, w, "Extended RCODE (upper 8 bits): 0x%x",
                     GET_DNS_OPT_EXTENDED_RCODE(dns->record[i].ttl));
    ADD_TEXT_ELEMENT(lw, w, "Version: 0x%x", GET_DNS_OPT_VERSION(dns->record[i].ttl));
    ADD_TEXT_ELEMENT(lw, w, "D0 (DNSSEC OK bit): %u", GET_DNS_OPT_D0(dns->record[i].ttl));
    opt = parse_dns_options(&dns->record[i]);
    n = list_begin(opt);
    while (n) {
        char buf[1024];
        struct dns_opt_rr *opt_rr;

        opt_rr = (struct dns_opt_rr *) list_data(n);
        for (int j = 0; j < opt_rr->option_length; j++) {
            snprintf(buf + 2 * j, 1024 - 2 * j, "%02x", opt_rr->data[j]);
        }
        ADD_TEXT_ELEMENT(lw, w, "Option code: %u", opt_rr->option_code);
        ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt_rr->option_length);
        ADD_TEXT_ELEMENT(lw, w, "Data: %s", buf);
        n = list_next(n);
    }
    free_dns_options(opt);
}

void add_nbns_information(list_view *lw, list_view_header *header, struct nbns_info *nbns)
{
    int records = 0;
    int answers = nbns->section_count[ANCOUNT];
    int authority = nbns->section_count[NSCOUNT];
    int additional = nbns->section_count[ARCOUNT];
    list_view_header *hdr;
    uint8_t flags;

    flags = nbns->aa << 6 | nbns->tc << 5 | nbns->rd << 4 | nbns->ra << 3 | nbns->broadcast;

    /* number of resource records */
    for (int i = 1; i < 4; i++) {
        records += nbns->section_count[i];
    }
    ADD_TEXT_ELEMENT(lw, header, "ID: 0x%x", nbns->id);
    ADD_TEXT_ELEMENT(lw, header, "Response flag: %d (%s)", nbns->r, nbns->r ? "Response" : "Request");
    ADD_TEXT_ELEMENT(lw, header, "Opcode: %d (%s)", nbns->opcode, get_nbns_opcode(nbns->opcode));
    hdr = ADD_SUB_HEADER(lw, header, selected[NBNS_FLAGS], NBNS_FLAGS, "Flags 0x%x", flags);
    add_flags(lw, hdr, flags, get_nbns_flags(), 6);
    ADD_TEXT_ELEMENT(lw, header, "Rcode: %d (%s)", nbns->rcode, get_nbns_rcode(nbns->rcode));
    ADD_TEXT_ELEMENT(lw, header, "Question Entries: %d, Answer RRs: %d, Authority RRs: %d, Additional RRs: %d",
                     nbns->section_count[QDCOUNT], answers, authority, additional);

    /* question entry */
    if (nbns->section_count[QDCOUNT]) {
        list_view_header *hdr;

        hdr = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Questions");
        ADD_TEXT_ELEMENT(lw, hdr, "Question name: %s, Question type: %s, Question class: IN (Internet)",
                         nbns->question.qname, get_nbns_type_extended(nbns->question.qtype));
        if (records) ADD_TEXT_ELEMENT(lw, hdr, "");
    }
    if (records) {
        list_view_header *hdr = NULL;

        if (answers) {
            hdr = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Answers");
            for (int i = 0; i < answers; i++) {
                add_nbns_record_hdr(lw, hdr, nbns, i);
            }
        }
        if (authority) {
            if (hdr) ADD_TEXT_ELEMENT(lw, hdr, "");
            hdr = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Authoritative nameservers");
            for (int i = 0; i < authority; i++) {
                add_nbns_record_hdr(lw, hdr, nbns, i + answers);
            }
        }
        if (additional) {
            if (hdr) ADD_TEXT_ELEMENT(lw, hdr, "");
            hdr = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Additional records");
            for (int i = 0; i < additional; i++) {
                add_nbns_record_hdr(lw, hdr, nbns, i + answers + authority);
            }
        }
    }
}

void add_nbns_record_hdr(list_view *lw, list_view_header *header, struct nbns_info *nbns, int i)
{
    char buffer[MAXLINE];
    list_view_header *hdr;

    snprintf(buffer, MAXLINE, "%s\t", nbns->record[i].rrname);
    snprintcat(buffer, MAXLINE, "IN\t");
    snprintcat(buffer, MAXLINE, "%s\t", get_nbns_type(nbns->record[i].rrtype));
    print_nbns_record(nbns, i, buffer, MAXLINE, nbns->record[i].rrtype);
    hdr = ADD_SUB_HEADER(lw, header, false, SUBLAYER, "%s", buffer);
    add_nbns_record(lw, hdr, nbns, i, buffer, MAXLINE, nbns->record[i].rrtype);
}

void add_nbns_record(list_view *lw, list_view_header *w, struct nbns_info *nbns, int i,
                     char *buf, int n, uint16_t type)
{
    char time[512];
    struct tm_t tm;

    ADD_TEXT_ELEMENT(lw, w, "Name: %s", nbns->record[i].rrname);
    ADD_TEXT_ELEMENT(lw, w, "Type: %s", get_nbns_type_extended(nbns->record[i].rrtype));
    if (nbns->record[i].rrclass == NBNS_IN) {
        ADD_TEXT_ELEMENT(lw, w, "Class: IN (Internet class)");
    } else {
        ADD_TEXT_ELEMENT(lw, w, "Class: %d", nbns->record[i].rrclass);
    }
    tm = get_time(nbns->record[i].ttl);
    time_ntop(&tm, time, 512);
    ADD_TEXT_ELEMENT(lw, w, "TTL: %s", time);

    switch (type) {
    case NBNS_NB:
    {
        list_view_header *hdr;
        uint16_t flags;

        flags = nbns->record[i].rdata.nb.g << 2 | nbns->record[i].rdata.nb.ont;
        hdr = ADD_SUB_HEADER(lw, w, selected[NBNS_FLAGS], NBNS_FLAGS, "NB flags (0x%x)", flags);
        add_flags(lw, hdr, flags, get_nbns_nb_flags(), 2);
        break;
    }
    case NBNS_NS:
        break;
    case NBNS_NBSTAT:
        break;
    default:
        break;
    }
}

void add_nbds_information(list_view *lw, list_view_header *header, struct nbds_info *nbds)
{
    list_view_header *hdr;
    char src_addr[INET_ADDRSTRLEN];
    char *type;

    if ((type = get_nbds_message_type(nbds->msg_type))) {
        ADD_TEXT_ELEMENT(lw, header, "Message type: 0x%x (%s)", nbds->msg_type, type);
    } else {
        ADD_TEXT_ELEMENT(lw, header, "Message type: 0x%x", nbds->msg_type);
    }
    hdr = ADD_SUB_HEADER(lw, header, selected[NBDS_FLAGS], NBDS_FLAGS, "Flags (0x%x)",
                         nbds->flags);
    add_flags(lw, hdr, nbds->flags, get_nbds_flags(), 4);
    ADD_TEXT_ELEMENT(lw, header, "Datagram id: 0x%x", nbds->dgm_id);
    inet_ntop(AF_INET, &nbds->source_ip, src_addr, INET_ADDRSTRLEN);
    ADD_TEXT_ELEMENT(lw, header, "Source IP: %s", src_addr);
    ADD_TEXT_ELEMENT(lw, header, "Source port: %u", nbds->source_port);

    switch (nbds->msg_type) {
    case NBDS_DIRECT_UNIQUE:
    case NBDS_DIRECT_GROUP:
    case NBDS_BROADCAST:
        ADD_TEXT_ELEMENT(lw, header, "Datagram length: %u bytes", nbds->msg.grp_unique->dgm_length);
        ADD_TEXT_ELEMENT(lw, header, "Packet offset: %u", nbds->msg.grp_unique->packet_offset);
        ADD_TEXT_ELEMENT(lw, header, "Source name: %s", nbds->msg.grp_unique->src_name);
        ADD_TEXT_ELEMENT(lw, header, "Destination name: %s", nbds->msg.grp_unique->dest_name);
        if (nbds->msg.grp_unique->data) {
            list_view_header *w = ADD_SUB_HEADER(lw, header, selected[SUBLAYER], SUBLAYER, "Data");

            add_hexdump(lw, w, HEXMODE_NORMAL, nbds->msg.grp_unique->data,
                        nbds->msg.grp_unique->data_size);
        }
        break;
    case NBDS_ERROR:
        ADD_TEXT_ELEMENT(lw, header, "Error code: %u", nbds->msg.error_code);
        break;
    case NBDS_QUERY_REQUEST:
    case NBDS_POSITIVE_QUERY_RESPONSE:
    case NBDS_NEGATIVE_QUERY_RESPONSE:
        ADD_TEXT_ELEMENT(lw, header, "Destination name: %s", nbds->msg.dest_name);
        break;

    default:
        break;
    }
}

void add_ssdp_information(list_view *lw, list_view_header *header, list_t *ssdp)
{
    const node_t *n;

    n = list_begin(ssdp);
    while (n) {
        ADD_TEXT_ELEMENT(lw, header, "%s", (char *) list_data(n));
        n = list_next(n);
    }
}

void add_http_information(list_view *lw, list_view_header *header, struct http_info *http)
{
}

/*
 * Display the bit values of flags
 *
 * flags contains the flag values
 * num_flags is the size of packet_flags
 * packet_flags is an array that contains a name/description of the specific flag,
 * its width (which is the number of bits in the flag), and, based on the value of
 * the flag, a description of the specific field value, see decoder/packet.h.
 */
void add_flags(list_view *lw, list_view_header *header, uint16_t flags, struct packet_flags *pf, int num_flags)
{
    char buf[MAXLINE];
    int num_bits = 0;

    for (int i = 0; i < num_flags; i++) {
        num_bits += pf[i].width;
    }
    for (int i = 0; i < num_bits; i++) {
        snprintf(buf + i, MAXLINE - i, ".");
    }
    for (int i = 0, k = 0; k < num_bits; i++) {
        /* print the bits of the flag 'i' */
        for (int j = 0; j < pf[i].width; j++) {
            buf[k + j] = ((flags >> (num_bits - (k + j) - 1)) & 0x01) + '0';
        }
        /* print the flag description */
        snprintf(buf + num_bits, MAXLINE - num_bits, "  %s", pf[i].str);
        if (pf[i].sflags) {
            uint8_t bf;

            /* print the field description based on index (bit value of field) */
            bf = (flags >> (num_bits - (k + pf[i].width))) & ((1 << pf[i].width) - 1);
            snprintcat(buf, MAXLINE, " %s", pf[i].sflags[bf]);
        }
        ADD_TEXT_ELEMENT(lw, header, "%s", buf);
        for (int j = 0; j < pf[i].width; j++) {
            buf[k + j] = '.';
        }
        k += pf[i].width;
    }
    ADD_TEXT_ELEMENT(lw, header, "");
}
