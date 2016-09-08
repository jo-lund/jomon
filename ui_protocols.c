#include <arpa/inet.h>
#include <net/if_arp.h>
#include <linux/igmp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <ctype.h>
#include "ui_layout.h"
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
static void print_llc(char *buf, int n, struct eth_info *eth);
static void print_ip(char *buf, int n, struct ip_info *info);
static void print_udp(char *buf, int n, struct ip_info *info);
static void print_tcp(char *buf, int n, struct ip_info *info);
static void print_icmp(char *buf, int n, struct ip_info *info);
static void print_igmp(char *buf, int n, struct ip_info *info);
static void print_dns(char *buf, int n, struct dns_info *dns);
static void print_nbns(char *buf, int n, struct nbns_info *nbns);
static void print_ssdp(char *buf, int n, list_t *ssdp);
static void print_http(char *buf, int n, struct http_info *http);
static void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type, bool *soa);
static void print_nbns_record(struct nbns_info *info, int i, char *buf, int n, uint16_t type);

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
        print_llc(buf, size, &p->eth);
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

/* print Ethernet 802.3 frame information */
void print_llc(char *buf, int n, struct eth_info *eth)
{
    if (eth->llc->dsap == 0x42 && eth->llc->ssap == 0x42) {
        char smac[HW_ADDRSTRLEN];
        char dmac[HW_ADDRSTRLEN];

        snprintf(smac, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
                 eth->mac_src[0], eth->mac_src[1], eth->mac_src[2],
                 eth->mac_src[3], eth->mac_src[4], eth->mac_src[5]);
        snprintf(dmac, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
                 eth->mac_dst[0], eth->mac_dst[1], eth->mac_dst[2],
                 eth->mac_dst[3], eth->mac_dst[4], eth->mac_dst[5]);
        switch (eth->llc->bpdu->type) {
        case CONFIG:
            PRINT_LINE(buf, n, smac, dmac, "STP", "Configuration BPDU");
            break;
        case RST:
            PRINT_LINE(buf, n, smac, dmac, "STP", "Rapid Spanning Tree BPDU. Root Path Cost: %u  Port ID: 0x%x",
                       eth->llc->bpdu->root_pc, eth->llc->bpdu->port_id);
            break;
        case TCN:
            PRINT_LINE(buf, n, smac, dmac, "STP", "Topology Change Notification BPDU");
            break;
        }
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
        PRINT_INFO(buf, n, "%s ", get_dns_class(dns->record[0].rrclass));
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

void print_ethernet_verbose(WINDOW *win, struct packet *p, int y)
{
    char src[HW_ADDRSTRLEN];
    char dst[HW_ADDRSTRLEN];

    snprintf(src, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             p->eth.mac_src[0], p->eth.mac_src[1], p->eth.mac_src[2],
             p->eth.mac_src[3], p->eth.mac_src[4], p->eth.mac_src[5]);
    snprintf(dst, HW_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             p->eth.mac_dst[0], p->eth.mac_dst[1], p->eth.mac_dst[2],
             p->eth.mac_dst[3], p->eth.mac_dst[4], p->eth.mac_dst[5]);
    mvwprintw(win, y, 4, "MAC source: %s", src);
    mvwprintw(win, ++y, 4, "MAC destination: %s", dst);
    mvwprintw(win, ++y, 4, "Ethertype: 0x%x", p->eth.ethertype);
}

void print_llc_verbose(WINDOW *win, struct packet *p, int y)
{
    mvwprintw(win, y, 4, "DSAP: 0x%x", p->eth.llc->dsap);
    mvwprintw(win, ++y, 4, "SSAP: 0x%x", p->eth.llc->ssap);
    mvwprintw(win, ++y, 4, "Control: 0x%x", p->eth.llc->control);
}

void print_arp_verbose(WINDOW *win, struct packet *p, int y)
{
    mvwprintw(win, y, 4, "Hardware type: %d (%s)", p->eth.arp->ht, get_arp_hardware_type(p->eth.arp->ht));
    mvwprintw(win, ++y, 4, "Protocol type: 0x%x (%s)", p->eth.arp->pt, get_arp_protocol_type(p->eth.arp->pt));
    mvwprintw(win, ++y, 4, "Hardware size: %d", p->eth.arp->hs);
    mvwprintw(win, ++y, 4, "Protocol size: %d", p->eth.arp->ps);
    mvwprintw(win, ++y, 4, "Opcode: %d (%s)", p->eth.arp->op, get_arp_opcode(p->eth.arp->op));
    mvwprintw(win, ++y, 0, "");
    mvwprintw(win, ++y, 4, "Sender IP: %-15s  HW: %s", p->eth.arp->sip, p->eth.arp->sha);
    mvwprintw(win, ++y, 4, "Target IP: %-15s  HW: %s", p->eth.arp->tip, p->eth.arp->tha);
}

void print_stp_verbose(WINDOW *win, struct packet *p, int y)
{
    mvwprintw(win, y, 4, "Protocol Id: %d", p->eth.llc->bpdu->protocol_id);
    mvwprintw(win, ++y, 4, "Version: %d", p->eth.llc->bpdu->version);
    mvwprintw(win, ++y, 4, "Type: %d (%s)", p->eth.llc->bpdu->type, get_stp_bpdu_type(p->eth.llc->bpdu->type));
    if (p->eth.llc->bpdu->type == CONFIG || p->eth.llc->bpdu->type == RST) {
        char buf[1024];

        memset(buf, 0, 1024);
        snprintcat(buf, 1024, "Flags: ");
        if (p->eth.llc->bpdu->tcack) snprintcat(buf, 1024, "Topology Change Ack, ");
        if (p->eth.llc->bpdu->agreement) snprintcat(buf, 1024, "Agreement, ");
        if (p->eth.llc->bpdu->forwarding) snprintcat(buf, 1024, "Forwarding, ");
        if (p->eth.llc->bpdu->learning) snprintcat(buf, 1024, "Learning, ");
        if (p->eth.llc->bpdu->proposal) snprintcat(buf, 1024, "Topology Change, ");
        if (p->eth.llc->bpdu->port_role) {
            snprintcat(buf, 1024, "Port Role: ");
            if (p->eth.llc->bpdu->port_role == 0x01) snprintcat(buf, 1024, "Backup");
            if (p->eth.llc->bpdu->port_role == 0x02) snprintcat(buf, 1024, "Root");
            if (p->eth.llc->bpdu->port_role == 0x03) snprintcat(buf, 1024, "Designated");
        }
        mvwprintw(win, ++y, 4, "%s", buf);
        mvwprintw(win, ++y, 4, "Root ID: %u/%02x.%02x.%02x.%02x.%02x.%02x", p->eth.llc->bpdu->root_id[0] << 8 |
                  p->eth.llc->bpdu->root_id[1], p->eth.llc->bpdu->root_id[2], p->eth.llc->bpdu->root_id[3],
                  p->eth.llc->bpdu->root_id[4], p->eth.llc->bpdu->root_id[5], p->eth.llc->bpdu->root_id[6],
                  p->eth.llc->bpdu->root_id[7]);
        mvwprintw(win, ++y, 4, "Root Path Cost: %d", p->eth.llc->bpdu->root_pc);
        mvwprintw(win, ++y, 4, "Bridge ID: %u/%02x.%02x.%02x.%02x.%02x.%02x", p->eth.llc->bpdu->bridge_id[0] << 8 |
                  p->eth.llc->bpdu->bridge_id[1], p->eth.llc->bpdu->bridge_id[2], p->eth.llc->bpdu->bridge_id[3],
                  p->eth.llc->bpdu->bridge_id[4], p->eth.llc->bpdu->bridge_id[5], p->eth.llc->bpdu->bridge_id[6],
                  p->eth.llc->bpdu->bridge_id[7]);
        mvwprintw(win, ++y, 4, "Port ID: 0x%x", p->eth.llc->bpdu->port_id);
        mvwprintw(win, ++y, 4, "Message Age: %u s.", p->eth.llc->bpdu->msg_age / 256);
        mvwprintw(win, ++y, 4, "Max Age: %u s.", p->eth.llc->bpdu->max_age / 256);
        mvwprintw(win, ++y, 4, "Hello Time: %u s.", p->eth.llc->bpdu->ht / 256);
        mvwprintw(win, ++y, 4, "Forward Delay: %u s.", p->eth.llc->bpdu->fd / 256);
    }
}

void print_ip_verbose(WINDOW *win, struct ip_info *ip, int y)
{
    mvwprintw(win, y, 4, "Version: %u", ip->version);
    mvwprintw(win, ++y, 4, "Internet Header Length (IHL): %u", ip->ihl);
    mvwprintw(win, ++y, 4, "Differentiated Services Code Point (DSCP): %u", ip->dscp);
    mvwprintw(win, ++y, 4, "Explicit Congestion Notification (ECN): %u", ip->ecn);
    mvwprintw(win, ++y, 4, "Total length: %u", ip->length);
    mvwprintw(win, ++y, 4, "Identification: %u", ip->id);
    mvwprintw(win, ++y, 4, "Flags: %u%u%u", ip->foffset & 0x80, ip->foffset & 0x40, ip->foffset & 0x20);
    mvwprintw(win, ++y, 4, "Time to live: %u", ip->ttl);
    mvwprintw(win, ++y, 4, "Protocol: %u", ip->protocol);
    mvwprintw(win, ++y, 4, "Checksum: %u", ip->checksum);
    mvwprintw(win, ++y, 4, "Source IP address: %s", ip->src);
    mvwprintw(win, ++y, 4, "Destination IP address: %s", ip->dst);
}

void print_icmp_verbose(WINDOW *win, struct ip_info *ip, int y)
{
    mvwprintw(win, y, 4, "Type: %d (%s)", ip->icmp.type, get_icmp_type(ip->icmp.type));
    switch (ip->icmp.type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        mvwprintw(win, ++y, 4, "Code: %d", ip->icmp.code);
        break;
    case ICMP_DEST_UNREACH:
        mvwprintw(win, ++y, 4, "Code: %d (%s)", ip->icmp.code, get_icmp_dest_unreach_code(ip->icmp.code));
        break;
    default:
        break;
    }
    mvwprintw(win, ++y, 4, "Checksum: %d", ip->icmp.checksum);
    if (ip->icmp.type == ICMP_ECHOREPLY || ip->icmp.type == ICMP_ECHO) {
        mvwprintw(win, ++y, 4, "Identifier: 0x%x", ip->icmp.echo.id);
        mvwprintw(win, ++y, 4, "Sequence number: %d", ip->icmp.echo.seq_num);
    }
}

void print_igmp_verbose(WINDOW *win, struct ip_info *info, int y)
{
    mvwprintw(win, y, 4, "Type: %d (%s) ", info->igmp.type, get_igmp_type(info->icmp.type));
    if (info->igmp.type == IGMP_HOST_MEMBERSHIP_QUERY) {
        if (!strcmp(info->igmp.group_addr, "0.0.0.0")) {
            mvwprintw(win, ++y, 4, "General query", info->igmp.type, get_igmp_type(info->icmp.type));
        } else {
            mvwprintw(win, ++y, 4, "Group-specific query", info->igmp.type, get_igmp_type(info->icmp.type));
        }
    }
    mvwprintw(win, ++y, 4, "Max response time: %d seconds", info->igmp.max_resp_time / 10);
    mvwprintw(win, ++y, 4, "Checksum: %d", info->igmp.checksum);
    mvwprintw(win, ++y, 4, "Group address: %s", info->igmp.group_addr);
    mvwprintw(win, ++y, 0, "");
}

void print_udp_verbose(WINDOW *win, struct ip_info *ip, int y)
{
    mvwprintw(win, y, 4, "Source port: %u", ip->udp.src_port);
    mvwprintw(win, ++y, 4, "Destination port: %u", ip->udp.dst_port);
    mvwprintw(win, ++y, 4, "Length: %u", ip->udp.len);
    mvwprintw(win, ++y, 4, "Checksum: %u", ip->udp.checksum);
}

void print_tcp_verbose(WINDOW *win, struct ip_info *ip, int y)
{
    mvwprintw(win, y, 4, "Source port: %u", ip->tcp.src_port);
    mvwprintw(win, ++y, 4, "Destination port: %u", ip->tcp.dst_port);
    mvwprintw(win, ++y, 4, "Sequence number: %u", ip->tcp.seq_num);
    mvwprintw(win, ++y, 4, "Acknowledgment number: %u", ip->tcp.ack_num);
    mvwprintw(win, ++y, 4, "Data offset: %u", ip->tcp.offset);
    mvwprintw(win, ++y, 4, "Flags: %u%u%u%u%u%u%u%u%u",
              ip->tcp.ns, ip->tcp.cwr, ip->tcp.ece, ip->tcp.urg, ip->tcp.ack,
              ip->tcp.psh, ip->tcp.rst, ip->tcp.syn, ip->tcp.fin);
    mvwprintw(win, ++y, 4, "Window size: %u", ip->tcp.window);
    mvwprintw(win, ++y, 4, "Checksum: %u", ip->tcp.checksum);
    mvwprintw(win, ++y, 4, "Urgent pointer: %u", ip->tcp.urg_ptr);
}

void print_dns_verbose(WINDOW *win, struct dns_info *dns, int y, int maxx)
{
    int records = 0;

    /* number of resource records */
    for (int i = 1; i < 4; i++) {
        records += dns->section_count[i];
    }
    mvwprintw(win, y, 4, "ID: 0x%x", dns->id);
    mvwprintw(win, ++y, 4, "QR: %d (%s)", dns->qr, dns->qr ? "DNS Response" : "DNS Query");
    mvwprintw(win, ++y, 4, "Opcode: %d (%s)", dns->opcode, get_dns_opcode(dns->opcode));
    mvwprintw(win, ++y, 4, "Flags: %d%d%d%d", dns->aa, dns->tc, dns->rd, dns->ra);
    mvwprintw(win, ++y, 4, "Rcode: %d (%s)", dns->rcode, get_dns_rcode(dns->rcode));
    mvwprintw(win, ++y, 4, "Question: %d, Answer: %d, Authority: %d, Additional records: %d",
              dns->section_count[QDCOUNT], dns->section_count[ANCOUNT],
              dns->section_count[NSCOUNT], dns->section_count[ARCOUNT]);
    mvwprintw(win, ++y, 0, "");
    for (int i = dns->section_count[QDCOUNT]; i > 0; i--) {
        mvwprintw(win, ++y, 4, "QNAME: %s, QTYPE: %s, QCLASS: %s",
                  dns->question.qname, get_dns_type_extended(dns->question.qtype),
                  get_dns_class_extended(dns->question.qclass));
    }
    if (records) {
        int len;

        mvwprintw(win, ++y, 4, "Resource records:");
        len = get_max_namelen(dns->record, records);
        for (int i = 0; i < records; i++) {
            char buffer[maxx];
            bool soa = false;

            snprintf(buffer, maxx, "%-*s", len + 4, dns->record[i].name);
            snprintcat(buffer, maxx, "%-6s", get_dns_class(dns->record[i].rrclass));
            snprintcat(buffer, maxx, "%-8s", get_dns_type(dns->record[i].type));
            print_dns_record(dns, i, buffer, maxx, dns->record[i].type, &soa);
            mvwprintw(win, ++y, 8, "%s", buffer);
            if (soa) {
                mvwprintw(win, ++y, 0, "");
                print_dns_soa(win, dns, i, y + 1, 8);
            }
        }
    }
}

void print_dns_soa(WINDOW *win, struct dns_info *info, int i, int y, int x)
{
    mvwprintw(win, y, x, "mname: %s", info->record[i].rdata.soa.mname);
    mvwprintw(win, ++y, x, "rname: %s", info->record[i].rdata.soa.rname);
    mvwprintw(win, ++y, x, "Serial: %d", info->record[i].rdata.soa.serial);
    mvwprintw(win, ++y, x, "Refresh: %d", info->record[i].rdata.soa.refresh);
    mvwprintw(win, ++y, x, "Retry: %d", info->record[i].rdata.soa.retry);
    mvwprintw(win, ++y, x, "Expire: %d", info->record[i].rdata.soa.expire);
    mvwprintw(win, ++y, x, "Minimum: %d", info->record[i].rdata.soa.minimum);
}

void print_nbns_verbose(WINDOW *win, struct nbns_info *nbns, int y, int maxx)
{
    int records = 0;

    /* number of resource records */
    for (int i = 1; i < 4; i++) {
        records += nbns->section_count[i];
    }
    mvwprintw(win, y, 4, "ID: 0x%x", nbns->id);
    mvwprintw(win, ++y, 4, "Response flag: %d (%s)", nbns->r, nbns->r ? "Response" : "Request");
    mvwprintw(win, ++y, 4, "Opcode: %d (%s)", nbns->opcode, get_nbns_opcode(nbns->opcode));
    mvwprintw(win, ++y, 4, "Flags: %d%d%d%d%d", nbns->aa, nbns->tc, nbns->rd, nbns->ra, nbns->broadcast);
    mvwprintw(win, ++y, 4, "Rcode: %d (%s)", nbns->rcode, get_nbns_rcode(nbns->rcode));
    mvwprintw(win, ++y, 4, "Question Entries: %d, Answer RRs: %d, Authority RRs: %d, Additional RRs: %d",
              nbns->section_count[QDCOUNT], nbns->section_count[ANCOUNT],
              nbns->section_count[NSCOUNT], nbns->section_count[ARCOUNT]);
    mvwprintw(win, ++y, 0, "");

    /* question entry */
    if (nbns->section_count[QDCOUNT]) {
        mvwprintw(win, ++y, 4, "Question name: %s, Question type: %s, Question class: IN (Internet)",
                  nbns->question.qname, get_nbns_type_extended(nbns->question.qtype));
    }

    if (records) {
        mvwprintw(win, ++y, 4, "Resource records:");
        for (int i = 0; i < records; i++) {
            char buffer[maxx];

            snprintf(buffer, maxx, "%s\t", nbns->record[i].rrname);
            snprintcat(buffer, maxx, "IN\t");
            snprintcat(buffer, maxx, "%s\t", get_nbns_type(nbns->record[i].rrtype));
            print_nbns_record(nbns, i, buffer, maxx, nbns->record[i].rrtype);
            mvwprintw(win, ++y, 8, "%s", buffer);
        }
    }
}

void print_ssdp_verbose(WINDOW *win, list_t *ssdp, int y)
{
    const node_t *n;

    n = list_begin(ssdp);
    while (n) {
        mvwprintw(win, y++, 4, "%s", (char *) list_data(n));
        n = list_next(n);
    }
}

void print_http_verbose(WINDOW *win, struct http_info *http, int y)
{

}

void print_payload(WINDOW *win, unsigned char *payload, uint16_t len, int y)
{
    int size = 1024;
    int num = 0;
    char buf[size];

    while (num < len) {
        snprintf(buf, size, "%08x  ", num);
        for (int i = num; i < num + 16; i++) {
            if (i < len) {
                snprintcat(buf, size, "%02x ", payload[i]);
            } else {
                snprintcat(buf, size, "   ");
            }
            if (i != 0 && i % 16 - 8 == 0) snprintcat(buf, size, " ");
        }
        snprintcat(buf, size, "|");
        for (int i = num; i < num + 16; i++) {
            if (i < len) {
                if (isprint(payload[i])) {
                    snprintcat(buf, size, "%c", payload[i]);
                } else {
                    snprintcat(buf, size, ".");
                }
            } else {
                snprintcat(buf, size, " ");
            }
        }
        snprintcat(buf, size, "|");
        num += 16;
        mvwprintw(win, y++, 4, "%s", buf);
    }
}
