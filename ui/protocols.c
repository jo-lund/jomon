#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/igmp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include "layout.h"
#include "layout_int.h"
#include "protocols.h"
#include "../misc.h"
#include "hexdump.h"
#include "../geoip.h"
#include "../decoder/decoder.h"
#include "../monitor.h"

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

extern int hexmode;
static void print_error(char *buf, int size, struct packet *p);
static void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type);
static void print_nbns_record(struct nbns_info *info, int i, char *buf, int n);
static void add_dns_soa(list_view *lw, list_view_header *w, struct dns_info *dns, int i);
static void add_dns_txt(list_view *lw, list_view_header *w, struct dns_info *dns, int i);
static void add_dns_opt(list_view *lw, list_view_header *w, struct dns_info *dns, int i);
static void add_dns_record_hdr(list_view *lw, list_view_header *header, struct dns_info *dns,
                               int idx, int max_record_name);
static void add_dns_record(list_view *lw, list_view_header *w, struct dns_info *info, int i,
                           uint16_t type);
static void add_nbns_record_hdr(list_view *lw, list_view_header *header, struct nbns_info *nbns, int i);
static void add_nbns_record(list_view *lw, list_view_header *w, struct nbns_info *nbnsn, int i,
                            uint16_t type);
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
static void add_snmp_pdu(list_view *lw, list_view_header *header, struct snmp_pdu *pdu);
static void add_snmp_trap(list_view *lw, list_view_header *header, struct snmp_trap *pdu);
static void add_snmp_variables(list_view *lw, list_view_header *header, list_t *vars);
static void add_tls_handshake(list_view *lw, list_view_header *header,
                              struct tls_handshake *handshake);
static void add_tls_client_hello(list_view *lw, list_view_header *header,
                                 struct tls_handshake_client_hello *hello);
static void add_tls_server_hello(list_view *lw, list_view_header *header,
                                 struct tls_handshake_server_hello *hello);
static void add_tls_extensions(list_view *lw, list_view_header *header,
                               unsigned char *data, uint16_t len);
static void add_dhcp_options(list_view *lw, list_view_header *header, struct dhcp_info *dhcp);

void write_to_buf(char *buf, int size, struct packet *p)
{
    if (p->perr != NO_ERR && p->perr != UNK_PROTOCOL) {
        print_error(buf, size, p);
    } else {
        struct protocol_info *pinfo = get_protocol(p->root->id);

        if (pinfo) {
            char time[TBUFLEN];
            struct timeval t = p->time;

            format_timeval(&t, time, TBUFLEN);
            PRINT_NUMBER(buf, size, p->num);
            PRINT_TIME(buf, size, time);
            pinfo->print_pdu(buf, size, p);
        } else if (p->len - ETH_HLEN)
            print_error(buf, size, p);
    }
}

void print_error(char *buf, int size, struct packet *p)
{
    char smac[HW_ADDRSTRLEN];
    char dmac[HW_ADDRSTRLEN];
    char time[TBUFLEN];

    HW_ADDR_NTOP(smac, eth_src(p));
    HW_ADDR_NTOP(dmac, eth_dst(p));
    format_timeval(&p->time, time, TBUFLEN);
    if (p->perr != NO_ERR && p->perr != UNK_PROTOCOL) {
        PRINT_LINE(buf, size, p->num, time, smac, dmac,
                   "ETH II", "Ethertype: 0x%x [decode error]", ethertype(p));
    } else { /* not yet supported */
        PRINT_LINE(buf, size, p->num, time, smac, dmac, "ETH II", "Ethertype: 0x%x",
                   ethertype(p));
    }
}

void print_arp(char *buf, int n, void *data)
{
    struct packet *p = data;
    struct arp_info *arp = get_arp(p);
    char sip[INET_ADDRSTRLEN];
    char tip[INET_ADDRSTRLEN];
    char sha[HW_ADDRSTRLEN];

    inet_ntop(AF_INET, arp->sip, sip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp->tip, tip, INET_ADDRSTRLEN);
    PRINT_ADDRESS(buf, n, sip, tip);
    PRINT_PROTOCOL(buf, n, "ARP");
    switch (arp->op) {
    case ARPOP_REQUEST:
        PRINT_INFO(buf, n, "Request: Looking for hardware address of %s", tip);
        break;
    case ARPOP_REPLY:
        HW_ADDR_NTOP(sha, arp->sha);
        PRINT_INFO(buf, n, "Reply: %s has hardware address %s", sip, sha);
        break;
    default:
        PRINT_INFO(buf, n, "Opcode %d", arp->op);
        break;
    }
}

void print_llc(char *buf, int n, void *data)
{
    struct packet *p = data;
    struct packet_data *pdata = p->root->next;
    struct protocol_info *pinfo;
    char smac[HW_ADDRSTRLEN];
    char dmac[HW_ADDRSTRLEN];

    HW_ADDR_NTOP(smac, eth_src(p));
    HW_ADDR_NTOP(dmac, eth_dst(p));
    PRINT_ADDRESS(buf, n, smac, dmac);
    pinfo = get_protocol(pdata->id);
    if (pinfo && pdata->next)
        pinfo->print_pdu(buf, n, pdata->next);
    else {
        PRINT_PROTOCOL(buf, n, "LLC");
        PRINT_INFO(buf, n, "SSAP: 0x%x  DSAP: 0x%x  Control: 0x%x",
                   llc_ssap(p), llc_dsap(p), llc_control(p));
    }
}

void print_stp(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct stp_info *stp = pdata->data;

    PRINT_PROTOCOL(buf, n, "STP");
    switch (stp->type) {
    case CONFIG:
        PRINT_INFO(buf, n, "Configuration BPDU");
        break;
    case RST:
        PRINT_INFO(buf, n, "Rapid Spanning Tree BPDU. Root Path Cost: %u  Port ID: 0x%x",
                   stp->root_pc, stp->root_id);
        break;
    case TCN:
        PRINT_INFO(buf, n, "Topology Change Notification BPDU");
        break;
    }
}

void print_snap(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct snap_info *snap = pdata->data;

    PRINT_PROTOCOL(buf, n, "SNAP");
    PRINT_INFO(buf, n, "OUI: 0x%06x  Protocol Id: 0x%04x",
               snap->oui, snap->protocol_id);
}

void print_ipv4(char *buf, int n, void *data)
{
    struct packet *p = data;
    struct packet_data *pdata = p->root->next;
    struct ipv4_info *ip = pdata->data;
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip->src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->dst, dst, INET_ADDRSTRLEN);
    PRINT_ADDRESS(buf, n, src, dst);

    struct protocol_info *pinfo = get_protocol(pdata->id);

    if (pinfo && pdata->next)
        pinfo->print_pdu(buf, n, pdata->next);
    else {
        PRINT_PROTOCOL(buf, n, "IPv4");
        PRINT_INFO(buf, n, "Next header: %d", ip->protocol);
    }
}

void print_ipv6(char *buf, int n, void *data)
{
    struct packet *p = data;
    struct packet_data *pdata = p->root->next;
    struct ipv6_info *ip = pdata->data;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, ip->src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, ip->dst, dst, INET6_ADDRSTRLEN);
    PRINT_ADDRESS(buf, n, src, dst);

    struct protocol_info *pinfo = get_protocol(pdata->id);

    if (pinfo && pdata->next)
        pinfo->print_pdu(buf, n, pdata->next);
    else {
        PRINT_PROTOCOL(buf, n, "IPv6");
        PRINT_INFO(buf, n, "Next header: %d", ip->next_header);
    }
}

void print_icmp(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct icmp_info *icmp = pdata->data;
    char org[32];
    char rcvd[32];
    char xmit[32];
    char addr[INET_ADDRSTRLEN];

    PRINT_PROTOCOL(buf, n, "ICMP");
    switch (icmp->type) {
    case ICMP_ECHOREPLY:
        PRINT_INFO(buf, n, "Echo reply:   id = 0x%x  seq = %d", icmp->echo.id, icmp->echo.seq_num);
        break;
    case ICMP_ECHO:
        PRINT_INFO(buf, n, "Echo request: id = 0x%x  seq = %d", icmp->echo.id, icmp->echo.seq_num);
        break;
    case ICMP_DEST_UNREACH:
        PRINT_INFO(buf, n, "%s", get_icmp_dest_unreach_code(icmp->code));
        break;
    case ICMP_REDIRECT:
        inet_ntop(AF_INET, &icmp->gateway, addr, INET_ADDRSTRLEN);
        PRINT_INFO(buf, n, "Redirect to %s", addr);
        break;
    case ICMP_TIMESTAMP:
        PRINT_INFO(buf, n, "Timestamp request: id = 0x%x  seq = %d, originate = %s, receive = %s, transmit = %s",
                   icmp->echo.id, icmp->echo.seq_num, get_time_from_ms_ut(icmp->timestamp.originate, org, 32),
                   get_time_from_ms_ut(icmp->timestamp.receive, rcvd, 32),
                   get_time_from_ms_ut(icmp->timestamp.transmit, xmit, 32));
        break;
    case ICMP_TIMESTAMPREPLY:
        PRINT_INFO(buf, n, "Timestamp reply  : id = 0x%x  seq = %d, originate = %s, receive = %s, transmit = %s",
                   icmp->echo.id, icmp->echo.seq_num, get_time_from_ms_ut(icmp->timestamp.originate, org, 32),
                   get_time_from_ms_ut(icmp->timestamp.receive, rcvd, 32),
                   get_time_from_ms_ut(icmp->timestamp.transmit, xmit, 32));
        break;
    case ICMP_ADDRESS:
        inet_ntop(AF_INET, &icmp->addr_mask, addr, INET_ADDRSTRLEN);
        PRINT_INFO(buf, n, "Address mask request: id = 0x%x  seq = %d, mask = %s",
                   icmp->echo.id, icmp->echo.seq_num, addr);
        break;
    case ICMP_ADDRESSREPLY:
        inet_ntop(AF_INET, &icmp->addr_mask, addr, INET_ADDRSTRLEN);
        PRINT_INFO(buf, n, "Address mask reply:   id = 0x%x  seq = %d, mask = %s",
                   icmp->echo.id, icmp->echo.seq_num, addr);
        break;
    default:
        PRINT_INFO(buf, n, "%s", get_icmp_type(icmp->type));
        break;
    }
}

void print_igmp(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct igmp_info *igmp = pdata->data;

    char addr[INET_ADDRSTRLEN];

    PRINT_PROTOCOL(buf, n, "IGMP");
    switch (igmp->type) {
    case IGMP_MEMBERSHIP_QUERY:
        PRINT_INFO(buf, n, "Membership query  Max response time: %d seconds",
                   igmp->max_resp_time / 10);
        break;
    case IGMP_V1_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "Membership report");
        break;
    case IGMP_V2_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "IGMP2 Membership report");
        break;
    case IGMP_V2_LEAVE_GROUP:
        PRINT_INFO(buf, n, "Leave group");
        break;
    default:
        PRINT_INFO(buf, n, "Type 0x%x", igmp->type);
        break;
    }
    inet_ntop(AF_INET, &igmp->group_addr, addr, INET_ADDRSTRLEN);
    PRINT_INFO(buf, n, "  Group address: %s", addr);
}

void print_pim(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct pim_info *pim = pdata->data;
    char *type = get_pim_message_type(pim->type);

    PRINT_PROTOCOL(buf, n, "PIM");
    if (type) {
        PRINT_INFO(buf, n, "Message type: %s", type);
    } else {
        PRINT_INFO(buf, n, "Message type: %d", pim->type);
    }
}

void print_tcp(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct tcp *tcp = pdata->data;
    struct protocol_info *pinfo = get_protocol(pdata->id);

    if (pinfo && pdata->next)
        pinfo->print_pdu(buf, n, pdata->next);
    else {
        PRINT_PROTOCOL(buf, n, "TCP");
        PRINT_INFO(buf, n, "Source port: %d  Destination port: %d",
                   tcp->sport, tcp->dport);
        PRINT_INFO(buf, n, "  Flags:");
        if (tcp->fin) {
            PRINT_INFO(buf, n, " FIN");
        }
        if (tcp->syn) {
            PRINT_INFO(buf, n, " SYN");
        }
        if (tcp->rst) {
            PRINT_INFO(buf, n, " RST");
        }
        if (tcp->psh) {
            PRINT_INFO(buf, n, " PSH");
        }
        if (tcp->ack) {
            PRINT_INFO(buf, n, " ACK");
        }
        if (tcp->urg) {
            PRINT_INFO(buf, n, " URG");
        }
        PRINT_INFO(buf, n, "  seq: %u  ack: %u  win: %u",
                   tcp->seq_num, tcp->ack_num, tcp->window);
    }
}

void print_udp(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct udp_info *udp = pdata->data;
    struct protocol_info *pinfo = get_protocol(pdata->id);

    if (pinfo && pdata->next)
        pinfo->print_pdu(buf, n, pdata->next);
    else {
        PRINT_PROTOCOL(buf, n, "UDP");
        PRINT_INFO(buf, n, "Source port: %d  Destination port: %d",
                   udp->sport, udp->dport);
    }
}

void print_dns(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct dns_info *dns = pdata->data;

    if (get_protocol_key(pdata->id) == DNS) {
        PRINT_PROTOCOL(buf, n, "DNS");
    } else if (get_protocol_key(pdata->id) == MDNS) {
        PRINT_PROTOCOL(buf, n, "MDNS");
    } else {
        PRINT_PROTOCOL(buf, n, "LLMNR");
    }
    if (dns->qr == 0) {
        switch (dns->opcode) {
        case DNS_QUERY:
            if (dns->question) {
                PRINT_INFO(buf, n, "Standard query: ");
                PRINT_INFO(buf, n, "%s ", dns->question[0].qname);
                PRINT_INFO(buf, n, "%s", get_dns_type(dns->question[0].qtype));
            }
            break;
        case DNS_IQUERY:
            PRINT_INFO(buf, n, "Inverse query");
            break;
        case DNS_STATUS:
            PRINT_INFO(buf, n, "Server status request");
            break;
        }
    } else {
        if (dns->rcode == DNS_NO_ERROR) {
            PRINT_INFO(buf, n, "Response: ");
        } else {
            PRINT_INFO(buf, n, "Response: %s ", get_dns_rcode(dns->rcode));
        }
        if (dns->question) {
            PRINT_INFO(buf, n, "%s ", dns->question[0].qname);
        }
        if (dns->record) {
            for (unsigned int i = 0; i < dns->section_count[ANCOUNT]; i++) {
                PRINT_INFO(buf, n, "%s ", get_dns_type(dns->record[i].type));
                print_dns_record(dns, i, buf, n, dns->record[i].type);
                PRINT_INFO(buf, n, " ");
            }
        }
    }
}

void print_nbns(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct nbns_info *nbns = pdata->data;

    PRINT_PROTOCOL(buf, n, "NBNS");
    if (nbns->r == 0) {
        char opcode[16];

        strncpy(opcode, get_nbns_opcode(nbns->opcode), sizeof(opcode));
        PRINT_INFO(buf, n, "Name %s request: ", string_tolower(opcode));
        PRINT_INFO(buf, n, "%s ", nbns->question.qname);
        PRINT_INFO(buf, n, "%s ", get_nbns_type(nbns->question.qtype));
        if (nbns->section_count[ARCOUNT]) {
            print_nbns_record(nbns, 0, buf, n);
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
        PRINT_INFO(buf, n, "Name %s response: ", string_tolower(opcode));
        PRINT_INFO(buf, n, "%s ", nbns->record[0].rrname);
        PRINT_INFO(buf, n, "%s ", get_nbns_type(nbns->record[0].rrtype));
        print_nbns_record(nbns, 0, buf, n);
    }
}

void print_nbds(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct nbds_info *nbds = pdata->data;
    char *type;

    PRINT_PROTOCOL(buf, n, "NBDS");
    if ((type = get_nbds_message_type(nbds->msg_type))) {
        PRINT_INFO(buf, n, "%s", type);
    }
}

void print_ssdp(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct ssdp_info *ssdp = pdata->data;
    const node_t *node;

    PRINT_PROTOCOL(buf, n, "SSDP");
    node = list_begin(ssdp->fields);
    if (node) {
        PRINT_INFO(buf, n, (char *) list_data(node));
    }
}

void print_http(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct http_info *http = pdata->data;

    PRINT_PROTOCOL(buf, n, "HTTP");
    PRINT_INFO(buf, n, "%s", http->start_line);
}

void print_imap(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct imap_info *imap = pdata->data;

    PRINT_PROTOCOL(buf, n, "IMAP");
    if (imap->lines) {
        PRINT_INFO(buf, n, "%s", (char *) list_front(imap->lines));
    }
}

void print_smtp(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct smtp_info *smtp = pdata->data;

    PRINT_PROTOCOL(buf, n, "SMTP");
    if (smtp->data) {
        PRINT_INFO(buf, n, "C: Mail data");
    } else {
        if (smtp->response)
            PRINT_INFO(buf, n, "S: %s", smtp->start_line);
        else
            PRINT_INFO(buf, n, "C: %s", smtp->start_line);
    }
}

void print_tls(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct tls_info *tls = pdata->data;
    char *version = get_tls_version(tls->version);
    char *type = get_tls_type(tls->type);
    char records[MAXLINE];

    if (version) {
        PRINT_PROTOCOL(buf, n, version);
    } else {
        PRINT_PROTOCOL(buf, n, "TLS");
    }
    if (tls->type == TLS_HANDSHAKE) {
        snprintf(records, MAXLINE, "%s", get_tls_handshake_type(tls->handshake->type));
    } else {
        snprintf(records, MAXLINE, "%s", type);
    }
    tls = tls->next;
    while (tls) {
        if (tls->type == TLS_HANDSHAKE) {
            snprintcat(records, MAXLINE, ", %s", get_tls_handshake_type(tls->handshake->type));
        } else {
            snprintcat(records, MAXLINE, ", %s", type);
        }
        tls = tls->next;
    }
    PRINT_INFO(buf, n, "%s", records);
}

void print_dhcp(char *buf, int n, void *data)
{
    char hwaddr[HW_ADDRSTRLEN];
    struct dhcp_info *dhcp = (struct dhcp_info *)((struct packet_data *) data)->data;
    const node_t *node;

    PRINT_PROTOCOL(buf, n, "DHCP");
    LIST_FOREACH(dhcp->options, node) {
        struct dhcp_options *opt = (struct dhcp_options *) list_data(node);

        if (opt->tag == DHCP_MESSAGE_TYPE) {
            switch (opt->byte) {
            case DHCPDISCOVER:
                HW_ADDR_NTOP(hwaddr, dhcp->chaddr);
                PRINT_INFO(buf, n, "Discover  Transaction id: 0x%x", dhcp->xid);
                break;
            case DHCPOFFER:
                PRINT_INFO(buf, n, "Offer     Transaction id: 0x%x", dhcp->xid);
                break;
            case DHCPREQUEST:
                PRINT_INFO(buf, n, "Request   Transaction id: 0x%x", dhcp->xid);
                break;
            case DHCPDECLINE:
                PRINT_INFO(buf, n, "Decline   Transaction id: 0x%x", dhcp->xid);
                break;
            case DHCPACK:
                PRINT_INFO(buf, n, "ACK       Transaction id: 0x%x", dhcp->xid);
                break;
            case DHCPNAK:
                PRINT_INFO(buf, n, "NAK       Transaction id: 0x%x", dhcp->xid);
                break;
            case DHCPRELEASE:
                PRINT_INFO(buf, n, "Release   Transaction id: 0x%x", dhcp->xid);
                break;
            case DHCPINFORM:
                PRINT_INFO(buf, n, "Inform    Transaction id: 0x%x", dhcp->xid);
            default:
                break;
            }
            break;
        }
    }
}

void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type)
{
    switch (type) {
    case DNS_TYPE_A:
    {
        char addr[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, (struct in_addr *) &info->record[i].rdata.address, addr, sizeof(addr));
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

void print_nbns_record(struct nbns_info *info, int i, char *buf, int n)
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

            inet_ntop(AF_INET, (struct in_addr *) &info->record[i].rdata.nb.address[0], addr, sizeof(addr));
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

        inet_ntop(AF_INET, (struct in_addr *) &info->record[i].rdata.nsdipaddr, addr, sizeof(addr));
        snprintcat(buf, n, " NSD IP address: %s", addr);
        break;
    }
    case NBNS_NBSTAT:
        break;
    default:
        break;
    }
}

void print_snmp(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct snmp_info *snmp = pdata->data;
    char *type;
    list_t *vars;

    PRINT_PROTOCOL(buf, n, "SNMP");
    if ((type = get_snmp_type(snmp))) {
        PRINT_INFO(buf, n, "%s ", type);
    } else {
        PRINT_INFO(buf, n, "type: %d ", snmp->pdu_type);
    }
    if (snmp->pdu_type == SNMP_TRAP) {
        vars = snmp->trap->varbind_list;
    } else {
        vars = snmp->pdu->varbind_list;
    }
    if (vars) {
        const node_t *n = list_begin(vars);

        while (n) {
            struct snmp_varbind *var = (struct snmp_varbind *) list_data(n);

            PRINT_INFO(buf, MAXLINE, "%s ", var->object_name);
            n = list_next(n);
        }
    }
}

void add_ethernet_information(list_view *lw, list_view_header *header, struct packet *p)
{
    char line[MAXLINE];
    char src[HW_ADDRSTRLEN];
    char dst[HW_ADDRSTRLEN];
    char *type;
    struct eth_info *eth = ((struct packet_data *) p->root)->data;

    HW_ADDR_NTOP(src, eth->mac_src);
    HW_ADDR_NTOP(dst, eth->mac_dst);
    LV_ADD_TEXT_ELEMENT(lw, header, "MAC source: %s", src);
    LV_ADD_TEXT_ELEMENT(lw, header, "MAC destination: %s", dst);
    snprintf(line, MAXLINE, "Ethertype: 0x%x", eth->ethertype);
    if ((type = get_ethernet_type(eth->ethertype))) {
        snprintcat(line, MAXLINE, " (%s)", type);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, line);
}

void add_llc_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct eth_802_llc *llc = pdata->data;

    LV_ADD_TEXT_ELEMENT(lw, header, "Destination Service Access Point (DSAP): 0x%x", llc->dsap);
    LV_ADD_TEXT_ELEMENT(lw, header, "Source Service Access Point (SSAP): 0x%x", llc->ssap);
    LV_ADD_TEXT_ELEMENT(lw, header, "Control: 0x%x", llc->control);
}

void add_snap_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct snap_info *snap = pdata->data;

    LV_ADD_TEXT_ELEMENT(lw, header, "IEEE Organizationally Unique Identifier (OUI): 0x%06x",
                        snap->oui[0] << 16 | snap->oui[1] << 8 | snap->oui[2]);
    LV_ADD_TEXT_ELEMENT(lw, header, "Protocol Id: 0x%04x", snap->protocol_id);
}

void add_arp_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct arp_info *arp = pdata->data;
    char sip[INET_ADDRSTRLEN];
    char tip[INET_ADDRSTRLEN];
    char sha[HW_ADDRSTRLEN];
    char tha[HW_ADDRSTRLEN];
    char *hwtype;
    char *ptype;
    char *opcode;

    HW_ADDR_NTOP(sha, arp->sha);
    HW_ADDR_NTOP(tha, arp->tha);
    inet_ntop(AF_INET, arp->sip, sip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp->tip, tip, INET_ADDRSTRLEN);

    if ((hwtype = get_arp_hardware_type(arp->ht)) != NULL)
        LV_ADD_TEXT_ELEMENT(lw, header, "Hardware type: %s (%d)", hwtype, arp->ht);
    if ((ptype = get_arp_protocol_type(arp->pt)) != NULL)
        LV_ADD_TEXT_ELEMENT(lw, header, "Protocol type: %s (0x%x)", ptype, arp->pt);
    LV_ADD_TEXT_ELEMENT(lw, header, "Hardware size: %d", arp->hs);
    LV_ADD_TEXT_ELEMENT(lw, header, "Protocol size: %d", arp->ps);
    if ((opcode = get_arp_opcode(arp->op)) != NULL)
        LV_ADD_TEXT_ELEMENT(lw, header, "Opcode: %s (%d)", opcode, arp->op);
    LV_ADD_TEXT_ELEMENT(lw, header, "Sender IP: %-15s  HW: %s", sip, sha);
    LV_ADD_TEXT_ELEMENT(lw, header, "Target IP: %-15s  HW: %s", tip, tha);
}

void add_stp_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    uint16_t flags;
    struct stp_info *stp = pdata->data;;
    list_view_header *hdr;

    flags = stp->tcack << 7 | stp->agreement << 6 | stp->forwarding << 5 | stp->forwarding << 4 |
        stp->port_role << 2 | stp->proposal << 1 | stp->tc;
    LV_ADD_TEXT_ELEMENT(lw, header, "Protocol Id: %d", stp->protocol_id);
    LV_ADD_TEXT_ELEMENT(lw, header, "Version: %d", stp->version);
    LV_ADD_TEXT_ELEMENT(lw, header, "Type: %d (%s)", stp->type, get_stp_bpdu_type(stp->type));
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
        hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "%s (0x%x)", buf, flags);
        add_flags(lw, hdr, flags, get_stp_flags(), get_stp_flags_size());
        LV_ADD_TEXT_ELEMENT(lw, header, "Root ID: %u/%02x.%02x.%02x.%02x.%02x.%02x", stp->root_id[0] << 8 |
                  stp->root_id[1], stp->root_id[2], stp->root_id[3],
                  stp->root_id[4], stp->root_id[5], stp->root_id[6],
                  stp->root_id[7]);
        LV_ADD_TEXT_ELEMENT(lw, header, "Root Path Cost: %d", stp->root_pc);
        LV_ADD_TEXT_ELEMENT(lw, header, "Bridge ID: %u/%02x.%02x.%02x.%02x.%02x.%02x", stp->bridge_id[0] << 8 |
                  stp->bridge_id[1], stp->bridge_id[2], stp->bridge_id[3],
                  stp->bridge_id[4], stp->bridge_id[5], stp->bridge_id[6],
                  stp->bridge_id[7]);
        LV_ADD_TEXT_ELEMENT(lw, header, "Port ID: 0x%x", stp->port_id);
        LV_ADD_TEXT_ELEMENT(lw, header, "Message Age: %u s.", stp->msg_age / 256);
        LV_ADD_TEXT_ELEMENT(lw, header, "Max Age: %u s.", stp->max_age / 256);
        LV_ADD_TEXT_ELEMENT(lw, header, "Hello Time: %u s.", stp->ht / 256);
        LV_ADD_TEXT_ELEMENT(lw, header, "Forward Delay: %u s.", stp->fd / 256);
    }
}

void add_ipv4_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct ipv4_info *ip = pdata->data;
    char *protocol;
    char *dscp;
    char buf[MAXLINE];
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    list_view_header *hdr;
    uint8_t flags;

    flags = (ip->foffset & 0x8000) >> 13 | (ip->foffset & 0x4000) >> 13 |
        (ip->foffset & 0x2000) >> 13;
    LV_ADD_TEXT_ELEMENT(lw, header, "Version: %u", ip->version);
    LV_ADD_TEXT_ELEMENT(lw, header, "Internet Header Length (IHL): %u", ip->ihl);
    snprintf(buf, MAXLINE, "Differentiated Services Code Point (DSCP): 0x%x", ip->dscp);
    if ((dscp = get_ip_dscp(ip->dscp))) {
        snprintcat(buf, MAXLINE, " %s", dscp);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "%s", buf);
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
    LV_ADD_TEXT_ELEMENT(lw, header, "%s", buf);
    LV_ADD_TEXT_ELEMENT(lw, header, "Total length: %u", ip->length);
    LV_ADD_TEXT_ELEMENT(lw, header, "Identification: 0x%x (%u)", ip->id, ip->id);
    snprintf(buf, MAXLINE, "Flags: ");
    if (ip->foffset & 0x4000 || ip->foffset & 0x2000) {
        if (ip->foffset & 0x4000) snprintcat(buf, MAXLINE, "Don't Fragment ");
        if (ip->foffset & 0x2000) snprintcat(buf, MAXLINE, "More Fragments ");
    }
    snprintcat(buf, MAXLINE, "(0x%x)", flags);
    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "%s", buf, flags);
    add_flags(lw, hdr, flags, get_ipv4_flags(), get_ipv4_flags_size());
    LV_ADD_TEXT_ELEMENT(lw, header, "Fragment offset: %u", get_ipv4_foffset(ip));
    LV_ADD_TEXT_ELEMENT(lw, header, "Time to live: %u", ip->ttl);
    snprintf(buf, MAXLINE, "Protocol: %u", ip->protocol);
    if ((protocol = get_ip_transport_protocol(ip->protocol))) {
        snprintcat(buf, MAXLINE, " (%s)", protocol);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "%s", buf);
    LV_ADD_TEXT_ELEMENT(lw, header,"Checksum: %u", ip->checksum);
    inet_ntop(AF_INET, &ip->src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->dst, dst, INET_ADDRSTRLEN);
    if (ctx.opt.nogeoip) {
        LV_ADD_TEXT_ELEMENT(lw, header,"Source IP address: %s", src);
        LV_ADD_TEXT_ELEMENT(lw, header,"Destination IP address: %s", dst);
    } else {
        char buf[MAXLINE];

        LV_ADD_TEXT_ELEMENT(lw, header,"Source IP address: %s (GeoIP: %s)",
                            src, geoip_get_location(src, buf, MAXLINE));
        LV_ADD_TEXT_ELEMENT(lw, header,"Destination IP address: %s (GeoIP: %s)",
                         dst, geoip_get_location(dst, buf, MAXLINE));
    }
}

void add_ipv6_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct ipv6_info *ip = pdata->data;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    char *protocol;
    char buf[MAXLINE];

    inet_ntop(AF_INET6, ip->src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, ip->dst, dst, INET6_ADDRSTRLEN);
    LV_ADD_TEXT_ELEMENT(lw, header, "Version: %u", ip->version);
    LV_ADD_TEXT_ELEMENT(lw, header, "Traffic class: 0x%x", ip->tc);
    LV_ADD_TEXT_ELEMENT(lw, header, "Flow label: 0x%x", ip->flow_label);
    LV_ADD_TEXT_ELEMENT(lw, header, "Payload length: %u", ip->payload_len);
    snprintf(buf, MAXLINE, "Next header: %u", ip->next_header);
    if ((protocol = get_ip_transport_protocol(ip->next_header))) {
        snprintcat(buf, MAXLINE, " (%s)", protocol);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "%s", buf);
    LV_ADD_TEXT_ELEMENT(lw, header, "Hop limit: %u", ip->hop_limit);
    LV_ADD_TEXT_ELEMENT(lw, header, "Source address: %s", src);
    LV_ADD_TEXT_ELEMENT(lw, header, "Destination address: %s", dst);
}

void add_icmp_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct icmp_info *icmp = pdata->data;

    char addr[INET_ADDRSTRLEN];
    char time[32];

    LV_ADD_TEXT_ELEMENT(lw, header, "Type: %d (%s)", icmp->type, get_icmp_type(icmp->type));
    switch (icmp->type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Identifier: 0x%x", icmp->echo.id);
        LV_ADD_TEXT_ELEMENT(lw, header, "Sequence number: %d", icmp->echo.seq_num);
        break;
    case ICMP_DEST_UNREACH:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d (%s)", icmp->code, get_icmp_dest_unreach_code(icmp->code));
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        break;
    case ICMP_REDIRECT:
        inet_ntop(AF_INET, &icmp->gateway, addr, INET_ADDRSTRLEN);
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d (%s)", icmp->code, get_icmp_redirect_code(icmp->code));
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Gateway: %s", addr);
        break;
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Identifier: 0x%x", icmp->echo.id);
        LV_ADD_TEXT_ELEMENT(lw, header, "Sequence number: %d", icmp->echo.seq_num);
        LV_ADD_TEXT_ELEMENT(lw, header, "Originate timestamp: %s",
                         get_time_from_ms_ut(icmp->timestamp.originate, time, 32));
        LV_ADD_TEXT_ELEMENT(lw, header, "Receive timestamp: %s",
                         get_time_from_ms_ut(icmp->timestamp.receive, time, 32));
        LV_ADD_TEXT_ELEMENT(lw, header, "Tramsmit timestamp: %s",
                         get_time_from_ms_ut(icmp->timestamp.transmit, time, 32));
        break;
    case ICMP_ADDRESS:
    case ICMP_ADDRESSREPLY:
        inet_ntop(AF_INET, &icmp->addr_mask, addr, INET_ADDRSTRLEN);
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Identifier: 0x%x", icmp->echo.id);
        LV_ADD_TEXT_ELEMENT(lw, header, "Sequence number: %d", icmp->echo.seq_num);
        LV_ADD_TEXT_ELEMENT(lw, header, "Address mask: %s", addr);
        break;
    default:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        break;
    }
}

void add_igmp_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct igmp_info *igmp = pdata->data;
    char addr[INET_ADDRSTRLEN];
    char buf[MAXLINE];
    char *type;

    inet_ntop(AF_INET, &igmp->group_addr, addr, INET_ADDRSTRLEN);
    snprintf(buf, MAXLINE, "Type: %d", igmp->type);
    if ((type = get_igmp_type(igmp->type))) {
        snprintcat(buf, MAXLINE, " (%s)", type);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "%s", buf);
    if (igmp->type == IGMP_HOST_MEMBERSHIP_QUERY) {
        if (!strcmp(addr, "0.0.0.0")) {
            LV_ADD_TEXT_ELEMENT(lw, header, "General query");
        } else {
            LV_ADD_TEXT_ELEMENT(lw, header, "Group-specific query");
        }
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "Max response time: %d seconds", igmp->max_resp_time / 10);
    LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", igmp->checksum);
    LV_ADD_TEXT_ELEMENT(lw, header, "Group address: %s", addr);
}

void add_pim_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct pim_info *pim = pdata->data;
    char *type = get_pim_message_type(pim->type);

    LV_ADD_TEXT_ELEMENT(lw, header, "Version: %d", pim->version);
    if (type) {
        LV_ADD_TEXT_ELEMENT(lw, header, "Type: %d (%s)", pim->type, type);
    } else {
        LV_ADD_TEXT_ELEMENT(lw, header, "Type: %d", pim->type);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %u", pim->checksum);
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
    h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Hello Message (%d options)", list_size(opt));
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
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Holdtime: %s", time);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        case PIM_LAN_PRUNE_DELAY:
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "LAN Prune Delay");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            LV_ADD_TEXT_ELEMENT(lw, w, "Propagation delay: %u ms", hello->lan_prune_delay.prop_delay);
            LV_ADD_TEXT_ELEMENT(lw, w, "Override interval: %u ms", hello->lan_prune_delay.override_interval);
            break;
        case PIM_DR_PRIORITY:
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "DR Priority: %u", hello->dr_priority);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        case PIM_GENERATION_ID:
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Generation ID: %u", hello->gen_id);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        case PIM_STATE_REFRESH_CAPABLE:
            memset(&time, 0, 512);
            tm = get_time(hello->state_refresh.interval);
            time_ntop(&tm, time, 512);
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "State Refresh Capable");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            LV_ADD_TEXT_ELEMENT(lw, w, "Version: %u", hello->state_refresh.version);
            LV_ADD_TEXT_ELEMENT(lw, w, "Interval: %s", time);
            break;
        case PIM_ADDRESS_LIST:
        default:
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Unknown option: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        }
        n = list_next(n);
    }
    list_free(opt, free);
}

void add_pim_register(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Register Message");

    LV_ADD_TEXT_ELEMENT(lw, h, "Border bit: %d", pim->reg->border);
    LV_ADD_TEXT_ELEMENT(lw, h, "Null-Register bit: %d", pim->reg->null);
    if (pim->reg->data) {
        list_view_header *w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Data");

        add_hexdump(lw, w, hexmode, pim->reg->data, pim->reg->data_len);
    }
}

void add_pim_register_stop(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h;
    char *addr;

    h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Register-Stop Message");
    addr = get_pim_address(pim->assert->gaddr.addr_family, &pim->assert->gaddr.addr);
    if (addr) {
        LV_ADD_TEXT_ELEMENT(lw, h, "Group address: %s/%d", addr, pim->assert->gaddr.mask_len);
        free(addr);
    }
    addr = get_pim_address(pim->assert->saddr.addr_family, &pim->assert->saddr.addr);
    if (addr) {
        LV_ADD_TEXT_ELEMENT(lw, h, "Source address: %s", addr);
        free(addr);
    }
}

void add_pim_assert(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h;
    char *addr;

    h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Assert Message");
    addr = get_pim_address(pim->assert->gaddr.addr_family, &pim->assert->gaddr.addr);
    if (addr) {
        LV_ADD_TEXT_ELEMENT(lw, h, "Group address: %s/%d", addr, pim->assert->gaddr.mask_len);
        free(addr);
    }
    addr = get_pim_address(pim->assert->saddr.addr_family, &pim->assert->saddr.addr);
    if (addr) {
        LV_ADD_TEXT_ELEMENT(lw, h, "Source address: %s", addr);
        free(addr);
    }
    LV_ADD_TEXT_ELEMENT(lw, h, "RPTbit: %u", GET_RPTBIT(pim->assert->metric_pref));
    LV_ADD_TEXT_ELEMENT(lw, h, "Metric preference: %u", GET_METRIC_PREFERENCE(pim->assert->metric_pref));
    LV_ADD_TEXT_ELEMENT(lw, h, "Metric: %u", pim->assert->metric);
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
        h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Join/Prune Message");
        break;
    case PIM_GRAFT:
        h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Graft Message");
        break;
    case PIM_GRAFT_ACK:
        h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Graft Ack Message");
        break;
    default:
        return;
    }

    addr = get_pim_address(pim->jpg->neighbour.addr_family, &pim->jpg->neighbour.addr);
    if (addr) {
        LV_ADD_TEXT_ELEMENT(lw, h, "Upstream neighbour: %s", addr);
        free(addr);
    }
    tm = get_time(pim->jpg->holdtime);
    time_ntop(&tm, time, 512);
    LV_ADD_TEXT_ELEMENT(lw, h, "Holdtime: %s", time);

    grp = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Groups (%d)", pim->jpg->num_groups);

    for (int i = 0; i < pim->jpg->num_groups; i++) {
        list_view_header *joined;
        list_view_header *pruned;

        addr = get_pim_address(pim->jpg->groups[i].gaddr.addr_family, &pim->jpg->groups[i].gaddr.addr);
        if (addr) {
            LV_ADD_TEXT_ELEMENT(lw, grp, "Group address %d: %s/%d", i + 1, addr, pim->jpg->groups[i].gaddr.mask_len);
            free(addr);
        }

        joined = LV_ADD_SUB_HEADER(lw, grp, false, UI_SUBLAYER1, "Joined sources (%d)",
                                pim->jpg->groups[i].num_joined_src);
        for (int j = 0; j < pim->jpg->groups[i].num_joined_src; j++) {
            addr = get_pim_address(pim->jpg->groups[i].joined_src[j].addr_family,
                                   &pim->jpg->groups[i].joined_src[j].addr);
            if (addr) {
                LV_ADD_TEXT_ELEMENT(lw, joined, "Joined address %d: %s/%d", j + 1, addr,
                                 pim->jpg->groups[i].joined_src[j].mask_len);
                free(addr);
            }
        }
        pruned = LV_ADD_SUB_HEADER(lw, grp, false, UI_SUBLAYER1, "Pruned sources (%d)",
                                pim->jpg->groups[i].num_pruned_src);
        for (int j = 0; j < pim->jpg->groups[i].num_pruned_src; j++) {
            addr = get_pim_address(pim->jpg->groups[i].pruned_src[j].addr_family,
                                   &pim->jpg->groups[i].pruned_src[j].addr);
            if (addr) {
                LV_ADD_TEXT_ELEMENT(lw, pruned, "Pruned address %d: %s/%d", j + 1, addr,
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

    h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Bootstrap Message");
    LV_ADD_TEXT_ELEMENT(lw, h, "Fragment tag: 0x%x", pim->bootstrap->tag);
    LV_ADD_TEXT_ELEMENT(lw, h, "Hash mask length: %d", pim->bootstrap->hash_len);
    LV_ADD_TEXT_ELEMENT(lw, h, "BSR priority: %d", pim->bootstrap->priority);
    addr = get_pim_address(pim->bootstrap->bsr_addr.addr_family, &pim->bootstrap->bsr_addr.addr);
    if (addr) {
        LV_ADD_TEXT_ELEMENT(lw, h, "BSR address: %s", addr);
        free(addr);
    }
    addr = get_pim_address(pim->bootstrap->groups->gaddr.addr_family, &pim->bootstrap->groups->gaddr.addr);
    if (addr) {
        grp = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Group %s/%d", addr, pim->bootstrap->groups->gaddr.mask_len);
        LV_ADD_TEXT_ELEMENT(lw, grp, "RP count: %u", pim->bootstrap->groups->rp_count);
        LV_ADD_TEXT_ELEMENT(lw, grp, "Frag RP count: %u", pim->bootstrap->groups->frag_rp_count);
        for (int i = 0; i < pim->bootstrap->groups->frag_rp_count; i++) {
            char *rp_addr = get_pim_address(pim->bootstrap->groups->rps[i].rp_addr.addr_family,
                                         &pim->bootstrap->groups->rps[i].rp_addr.addr);
            if (rp_addr) {
                LV_ADD_TEXT_ELEMENT(lw, grp, "RP address %d: %s", i, rp_addr);
                free(rp_addr);
            }
            LV_ADD_TEXT_ELEMENT(lw, grp, "Holdtime: %u", pim->bootstrap->groups->rps[i].holdtime);
            LV_ADD_TEXT_ELEMENT(lw, grp, "Priority: %u", pim->bootstrap->groups->rps[i].priority);
        }
        free(addr);
    }
}

void add_pim_candidate(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h;
    char *addr;

    h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Candidate-RP-Advertisement Message");
    LV_ADD_TEXT_ELEMENT(lw, h, "Prefix count: %u", pim->candidate->prefix_count);
    LV_ADD_TEXT_ELEMENT(lw, h, "Priority: %u", pim->candidate->priority);
    LV_ADD_TEXT_ELEMENT(lw, h, "Holdtime: %u", pim->candidate->holdtime);
    addr = get_pim_address(pim->candidate->rp_addr.addr_family, &pim->candidate->rp_addr.addr);
    if (addr) {
        LV_ADD_TEXT_ELEMENT(lw, h, "RP address: %s", addr);
        free(addr);
    }
    for (int i = 0; i < pim->candidate->prefix_count; i++) {
        addr = get_pim_address(pim->candidate->gaddrs[i].addr_family, &pim->candidate->gaddrs[i].addr);
        if (addr) {
            LV_ADD_TEXT_ELEMENT(lw, h, "Group address %d: %s/%d", i, addr, pim->candidate->gaddrs[i].mask_len);
            free(addr);
        }
    }
}

void add_udp_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct udp_info *udp = pdata->data;

    LV_ADD_TEXT_ELEMENT(lw, header, "Source port: %u", udp->sport);
    LV_ADD_TEXT_ELEMENT(lw, header, "Destination port: %u", udp->dport);
    LV_ADD_TEXT_ELEMENT(lw, header, "Length: %u", udp->len);
    LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %u", udp->checksum);
}

void add_tcp_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct tcp *tcp = pdata->data;
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
    LV_ADD_TEXT_ELEMENT(lw, header, "Source port: %u", tcp->sport);
    LV_ADD_TEXT_ELEMENT(lw, header, "Destination port: %u", tcp->dport);
    LV_ADD_TEXT_ELEMENT(lw, header, "Sequence number: %u", tcp->seq_num);
    LV_ADD_TEXT_ELEMENT(lw, header, "Acknowledgment number: %u", tcp->ack_num);
    LV_ADD_TEXT_ELEMENT(lw, header, "Data offset: %u", tcp->offset);
    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "Flags: %s(0x%x)", buf, flags);
    add_flags(lw, hdr, flags, get_tcp_flags(), get_tcp_flags_size());
    LV_ADD_TEXT_ELEMENT(lw, header, "Window size: %u", tcp->window);
    LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %u", tcp->checksum);
    LV_ADD_TEXT_ELEMENT(lw, header, "Urgent pointer: %u", tcp->urg_ptr);
    if (tcp->options) {
        add_tcp_options(lw, header, tcp);
    }
}

void add_tcp_options(list_view *lw, list_view_header *header, struct tcp *tcp)
{
    list_t *options;
    const node_t *n;
    list_view_header *h;

    options = parse_tcp_options(tcp->options, (tcp->offset - 5) * 4);
    h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Options");
    n = list_begin(options);

    while (n) {
        struct tcp_options *opt = list_data(n);
        list_view_header *w;

        switch (opt->option_kind) {
        case TCP_OPT_NOP:
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "No operation");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_MSS:
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Maximum segment size: %u", opt->mss);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_WIN_SCALE:
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Window scale: %u", opt->win_scale);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_SAP:
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Selective Acknowledgement permitted");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_SACK:
        {
            const node_t *n = list_begin(opt->sack);

            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Selective Acknowledgement");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            while (n) {
                struct tcp_sack_block *block = list_data(n);

                LV_ADD_TEXT_ELEMENT(lw, w, "Left edge: %u", block->left_edge);
                LV_ADD_TEXT_ELEMENT(lw, w, "Right edge: %u", block->right_edge);
                n = list_next(n);
            }
            break;
        }
        case TCP_OPT_TIMESTAMP:
            w = LV_ADD_SUB_HEADER(lw, h, false, UI_SUBLAYER1, "Timestamp");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            LV_ADD_TEXT_ELEMENT(lw, w, "Timestamp value: %u", opt->ts.ts_val);
            LV_ADD_TEXT_ELEMENT(lw, w, "Timestamp echo reply: %u", opt->ts.ts_ecr);
            break;
        default:
            break;
        }
        n = list_next(n);
    }
    free_tcp_options(options);
}

void add_dns_information(void *w, void *sw, void *data)

{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct dns_info *dns = pdata->data;
    int records = 0;
    int answers = dns->section_count[ANCOUNT];
    int authority = dns->section_count[NSCOUNT];
    int additional = dns->section_count[ARCOUNT];
    list_view_header *hdr;
    uint16_t flags;

    if (get_protocol_key(pdata->id) == LLMNR) {
        flags = dns->llmnr_flags.c << 6 | dns->llmnr_flags.tc << 5 |
            dns->llmnr_flags.t << 4;
    } else {
        flags = dns->dns_flags.aa << 6 | dns->dns_flags.tc << 5 |
            dns->dns_flags.rd << 4 | dns->dns_flags.ra << 3;
    }

    /* number of resource records */
    for (int i = 1; i < 4; i++) {
        records += dns->section_count[i];
    }
    if (dns->length) {
        LV_ADD_TEXT_ELEMENT(lw, header, "Length: %u", dns->length);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "ID: 0x%x", dns->id);
    LV_ADD_TEXT_ELEMENT(lw, header, "QR: %d (%s)", dns->qr, dns->qr ? "DNS Response" : "DNS Query");
    LV_ADD_TEXT_ELEMENT(lw, header, "Opcode: %d (%s)", dns->opcode, get_dns_opcode(dns->opcode));

    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "Flags 0x%x", flags);
    if (pdata->id == LLMNR) {
        add_flags(lw, hdr, flags, get_llmnr_flags(), get_llmnr_flags_size());
    } else {
        add_flags(lw, hdr, flags, get_dns_flags(), get_dns_flags_size());
    }
    if (dns->qr) {
        LV_ADD_TEXT_ELEMENT(lw, header, "Rcode: %d (%s)", dns->rcode, get_dns_rcode(dns->rcode));
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "Question: %d, Answer: %d, Authority: %d, Additional records: %d",
                     dns->section_count[QDCOUNT], answers, authority, additional);
    if (dns->section_count[QDCOUNT]) {
        list_view_header *hdr;

        hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Questions");
        for (unsigned int i = 0; i < dns->section_count[QDCOUNT]; i++) {
            LV_ADD_TEXT_ELEMENT(lw, hdr, "QNAME: %s, QTYPE: %s, QCLASS: %s",
                             dns->question[i].qname, get_dns_type_extended(dns->question[i].qtype),
                             get_dns_class_extended(GET_MDNS_RRCLASS(dns->question[i].qclass)));
        }
    }
    if (records) {
        int len;
        list_view_header *hdr = NULL;

        if (answers) {
            len = get_dns_max_namelen(dns->record, answers);
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Answers");
            for (int i = 0; i < answers; i++) {
                add_dns_record_hdr(lw, hdr, dns, i, len);
            }
        }
        if (authority) {
            len = get_dns_max_namelen(dns->record + answers, authority);
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Authoritative nameservers");
            for (int i = 0; i < authority; i++) {
                add_dns_record_hdr(lw, hdr, dns, i + answers, len);
            }
        }
        if (additional) {
            len = get_dns_max_namelen(dns->record + answers + authority, additional);
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Additional records");
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
    w = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER2], UI_SUBLAYER2, "%s", buffer);
    add_dns_record(lw, w, dns, idx, dns->record[idx].type);
}

void add_dns_record(list_view *lw, list_view_header *w, struct dns_info *dns, int i, uint16_t type)
{
    char time[512];
    struct tm_t tm;

    if (dns->record[i].type != DNS_TYPE_OPT) {
        LV_ADD_TEXT_ELEMENT(lw, w, "Name: %s", dns->record[i].name);
        LV_ADD_TEXT_ELEMENT(lw, w, "Type: %s", get_dns_type_extended(dns->record[i].type));
        LV_ADD_TEXT_ELEMENT(lw, w, "Class: %s", get_dns_class_extended(GET_MDNS_RRCLASS(dns->record[i].rrclass)));
        tm = get_time(dns->record[i].ttl);
        time_ntop(&tm, time, 512);
        LV_ADD_TEXT_ELEMENT(lw, w, "TTL: %s", time);
    }

    switch (type) {
    case DNS_TYPE_SOA:
        add_dns_soa(lw, w, dns, i);
        break;
    case DNS_TYPE_MX:
        LV_ADD_TEXT_ELEMENT(lw, w, "Preference: %u", dns->record[i].rdata.mx.preference);
        LV_ADD_TEXT_ELEMENT(lw, w, "Mail exchange: %s", dns->record[i].rdata.mx.exchange);
        break;
    case DNS_TYPE_SRV:
        LV_ADD_TEXT_ELEMENT(lw, w, "Priority: %u", dns->record[i].rdata.srv.priority);
        LV_ADD_TEXT_ELEMENT(lw, w, "Weight: %u", dns->record[i].rdata.srv.weight);
        LV_ADD_TEXT_ELEMENT(lw, w, "Port: %u", dns->record[i].rdata.srv.port);
        LV_ADD_TEXT_ELEMENT(lw, w, "Target: %s", dns->record[i].rdata.srv.target);
        break;
    case DNS_TYPE_TXT:
        add_dns_txt(lw, w, dns, i);
        break;
    case DNS_TYPE_OPT:
        add_dns_opt(lw, w, dns, i);
        break;
    case DNS_TYPE_NSEC:
        LV_ADD_TEXT_ELEMENT(lw, w, "Next domain name: %s", dns->record[i].rdata.nsec.nd_name);
        for (unsigned int j = 0; j < dns->record[i].rdata.nsec.num_types; j++) {
            LV_ADD_TEXT_ELEMENT(lw, w, "Type in bitmap: %s",
                             get_dns_type_extended(dns->record[i].rdata.nsec.types[j]));
        }
        break;
    default:
        break;
    }
}

void add_dns_txt(list_view *lw, list_view_header *w, struct dns_info *dns, int i)
{
    const node_t *node = list_begin(dns->record[i].rdata.txt);

    while (node) {
        struct dns_txt_rr *rr = (struct dns_txt_rr *) list_data(node);

        LV_ADD_TEXT_ELEMENT(lw, w, "TXT: %s", (rr->txt == NULL) ? "" : rr->txt);
        LV_ADD_TEXT_ELEMENT(lw, w, "TXT length: %d", rr->len);
        node = list_next(node);
    }
}

void add_dns_soa(list_view *lw, list_view_header *w, struct dns_info *dns, int i)
{
    char time[512];
    struct tm_t tm;

    LV_ADD_TEXT_ELEMENT(lw, w, "mname (primary name server): %s", dns->record[i].rdata.soa.mname);
    LV_ADD_TEXT_ELEMENT(lw, w, "rname (mailbox of responsible authority): %s",
              dns->record[i].rdata.soa.rname);
    LV_ADD_TEXT_ELEMENT(lw, w, "Serial number: %u", dns->record[i].rdata.soa.serial);
    tm = get_time(dns->record[i].rdata.soa.refresh);
    time_ntop(&tm, time, 512);
    LV_ADD_TEXT_ELEMENT(lw, w, "Refresh interval: %d (%s)",
              dns->record[i].rdata.soa.refresh, time);
    tm = get_time(dns->record[i].rdata.soa.retry);
    time_ntop(&tm, time, 512);
    LV_ADD_TEXT_ELEMENT(lw, w, "Retry interval: %d (%s)",
              dns->record[i].rdata.soa.retry, time);
    tm = get_time(dns->record[i].rdata.soa.expire);
    time_ntop(&tm, time, 512);
    LV_ADD_TEXT_ELEMENT(lw, w, "Expire limit: %d (%s)",
              dns->record[i].rdata.soa.expire, time);
    tm = get_time(dns->record[i].rdata.soa.minimum);
    time_ntop(&tm, time, 512);
    LV_ADD_TEXT_ELEMENT(lw, w,  "Minimum TTL: %d (%s)",
              dns->record[i].rdata.soa.minimum, time);
}

void add_dns_opt(list_view *lw, list_view_header *w, struct dns_info *dns, int i)
{
    list_t *opt;
    const node_t *n;

    if (!dns->record[i].name[0]) {
        LV_ADD_TEXT_ELEMENT(lw, w, "Name: <root domain>");
    } else {
        LV_ADD_TEXT_ELEMENT(lw, w, "Name: %s", dns->record[i].name);
    }
    LV_ADD_TEXT_ELEMENT(lw, w, "Type: %s", get_dns_type_extended(dns->record[i].type));
    LV_ADD_TEXT_ELEMENT(lw, w, "UDP payload size: %u", GET_MDNS_RRCLASS(dns->record[i].rrclass));
    LV_ADD_TEXT_ELEMENT(lw, w, "Extended RCODE (upper 8 bits): 0x%x",
                     GET_DNS_OPT_EXTENDED_RCODE(dns->record[i].ttl));
    LV_ADD_TEXT_ELEMENT(lw, w, "Version: 0x%x", GET_DNS_OPT_VERSION(dns->record[i].ttl));
    LV_ADD_TEXT_ELEMENT(lw, w, "D0 (DNSSEC OK bit): %u", GET_DNS_OPT_D0(dns->record[i].ttl));
    opt = parse_dns_options(&dns->record[i]);
    n = list_begin(opt);
    while (n) {
        char buf[1024];
        struct dns_opt_rr *opt_rr;

        opt_rr = (struct dns_opt_rr *) list_data(n);
        for (int j = 0; j < opt_rr->option_length; j++) {
            snprintf(buf + 2 * j, 1024 - 2 * j, "%02x", opt_rr->data[j]);
        }
        LV_ADD_TEXT_ELEMENT(lw, w, "Option code: %u", opt_rr->option_code);
        LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt_rr->option_length);
        LV_ADD_TEXT_ELEMENT(lw, w, "Data: %s", buf);
        n = list_next(n);
    }
    free_dns_options(opt);
}

void add_nbns_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct nbns_info *nbns = pdata->data;
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
    LV_ADD_TEXT_ELEMENT(lw, header, "ID: 0x%x", nbns->id);
    LV_ADD_TEXT_ELEMENT(lw, header, "Response flag: %d (%s)", nbns->r, nbns->r ? "Response" : "Request");
    LV_ADD_TEXT_ELEMENT(lw, header, "Opcode: %d (%s)", nbns->opcode, get_nbns_opcode(nbns->opcode));
    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "Flags 0x%x", flags);
    add_flags(lw, hdr, flags, get_nbns_flags(), get_nbns_flags_size());
    LV_ADD_TEXT_ELEMENT(lw, header, "Rcode: %d (%s)", nbns->rcode, get_nbns_rcode(nbns->rcode));
    LV_ADD_TEXT_ELEMENT(lw, header, "Question Entries: %d, Answer RRs: %d, Authority RRs: %d, Additional RRs: %d",
                     nbns->section_count[QDCOUNT], answers, authority, additional);

    /* question entry */
    if (nbns->section_count[QDCOUNT]) {
        list_view_header *hdr;

        hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Questions");
        LV_ADD_TEXT_ELEMENT(lw, hdr, "Question name: %s, Question type: %s, Question class: IN (Internet)",
                         nbns->question.qname, get_nbns_type_extended(nbns->question.qtype));
    }
    if (records) {
        list_view_header *hdr = NULL;

        if (answers) {
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Answers");
            for (int i = 0; i < answers; i++) {
                add_nbns_record_hdr(lw, hdr, nbns, i);
            }
        }
        if (authority) {
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Authoritative nameservers");
            for (int i = 0; i < authority; i++) {
                add_nbns_record_hdr(lw, hdr, nbns, i + answers);
            }
        }
        if (additional) {
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Additional records");
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
    print_nbns_record(nbns, i, buffer, MAXLINE);
    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "%s", buffer);
    add_nbns_record(lw, hdr, nbns, i, nbns->record[i].rrtype);
}

void add_nbns_record(list_view *lw, list_view_header *w, struct nbns_info *nbns, int i,
                     uint16_t type)
{
    char time[512];
    struct tm_t tm;

    LV_ADD_TEXT_ELEMENT(lw, w, "Name: %s", nbns->record[i].rrname);
    LV_ADD_TEXT_ELEMENT(lw, w, "Type: %s", get_nbns_type_extended(nbns->record[i].rrtype));
    if (nbns->record[i].rrclass == NBNS_IN) {
        LV_ADD_TEXT_ELEMENT(lw, w, "Class: IN (Internet class)");
    } else {
        LV_ADD_TEXT_ELEMENT(lw, w, "Class: %d", nbns->record[i].rrclass);
    }
    tm = get_time(nbns->record[i].ttl);
    time_ntop(&tm, time, 512);
    LV_ADD_TEXT_ELEMENT(lw, w, "TTL: %s", time);

    switch (type) {
    case NBNS_NB:
    {
        list_view_header *hdr;
        uint16_t flags;

        flags = nbns->record[i].rdata.nb.g << 2 | nbns->record[i].rdata.nb.ont;
        hdr = LV_ADD_SUB_HEADER(lw, w, selected[UI_FLAGS], UI_FLAGS, "NB flags (0x%x)", flags);
        add_flags(lw, hdr, flags, get_nbns_nb_flags(), get_nbns_nb_flags_size());
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

void add_nbds_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct nbds_info *nbds = pdata->data;
    list_view_header *hdr;
    char src_addr[INET_ADDRSTRLEN];
    char *type;

    if ((type = get_nbds_message_type(nbds->msg_type))) {
        LV_ADD_TEXT_ELEMENT(lw, header, "Message type: 0x%x (%s)", nbds->msg_type, type);
    } else {
        LV_ADD_TEXT_ELEMENT(lw, header, "Message type: 0x%x", nbds->msg_type);
    }
    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "Flags (0x%x)",
                         nbds->flags);
    add_flags(lw, hdr, nbds->flags, get_nbds_flags(), get_nbds_flags_size());
    LV_ADD_TEXT_ELEMENT(lw, header, "Datagram id: 0x%x", nbds->dgm_id);
    inet_ntop(AF_INET, &nbds->source_ip, src_addr, INET_ADDRSTRLEN);
    LV_ADD_TEXT_ELEMENT(lw, header, "Source IP: %s", src_addr);
    LV_ADD_TEXT_ELEMENT(lw, header, "Source port: %u", nbds->source_port);

    switch (nbds->msg_type) {
    case NBDS_DIRECT_UNIQUE:
    case NBDS_DIRECT_GROUP:
    case NBDS_BROADCAST:
        LV_ADD_TEXT_ELEMENT(lw, header, "Datagram length: %u bytes", nbds->msg.dgm->dgm_length);
        LV_ADD_TEXT_ELEMENT(lw, header, "Packet offset: %u", nbds->msg.dgm->packet_offset);
        LV_ADD_TEXT_ELEMENT(lw, header, "Source name: %s", nbds->msg.dgm->src_name);
        LV_ADD_TEXT_ELEMENT(lw, header, "Destination name: %s", nbds->msg.dgm->dest_name);
        break;
    case NBDS_ERROR:
        LV_ADD_TEXT_ELEMENT(lw, header, "Error code: %u", nbds->msg.error_code);
        break;
    case NBDS_QUERY_REQUEST:
    case NBDS_POSITIVE_QUERY_RESPONSE:
    case NBDS_NEGATIVE_QUERY_RESPONSE:
        LV_ADD_TEXT_ELEMENT(lw, header, "Destination name: %s", nbds->msg.dest_name);
        break;

    default:
        break;
    }
}

void add_smb_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct smb_info *smb = pdata->data;
    char *cmd;
    list_view_header *hdr, *hdr2;

    LV_ADD_TEXT_ELEMENT(lw, header, "Protocol: %c%c%c", smb->protocol[1], smb->protocol[2],
                     smb->protocol[3]);
    if ((cmd = get_smb_command(smb->command)) != NULL) {
        LV_ADD_TEXT_ELEMENT(lw, header, "Command: %s", cmd);
    } else {
        LV_ADD_TEXT_ELEMENT(lw, header, "Command: 0x%x", smb->command);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "Status: %d", smb->status);
    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "Flags (0x%x)", smb->flags);
    add_flags(lw, hdr, smb->flags, get_smb_flags(), get_smb_flags_size());
    hdr2 = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "Flags2 (0x%x)", smb->flags2);
    add_flags(lw, hdr2, smb->flags2, get_smb_flags2(), get_smb_flags2_size());
    LV_ADD_TEXT_ELEMENT(lw, header, "PID: %d", smb->pidhigh << 16 | smb->pidlow);
    LV_ADD_TEXT_ELEMENT(lw, header, "Security features:");
    LV_ADD_TEXT_ELEMENT(lw, header, "Tree identifier: %d", smb->tid);
    LV_ADD_TEXT_ELEMENT(lw, header, "User identifier: %d", smb->uid);
    LV_ADD_TEXT_ELEMENT(lw, header, "Multiplex identifier: %d", smb->mid);
}

void add_ssdp_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct ssdp_info *ssdp = pdata->data;
    const node_t *n;

    n = list_begin(ssdp->fields);
    while (n) {
        LV_ADD_TEXT_ELEMENT(lw, header, "%s", (char *) list_data(n));
        n = list_next(n);
    }
}

void add_http_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct http_info *http = pdata->data;
    const rbtree_node_t *n;

    LV_ADD_TEXT_ELEMENT(lw, header, "%s", http->start_line);
    n = rbtree_first(http->header);
    while (n) {
        LV_ADD_TEXT_ELEMENT(lw, header, "%s: %s", rbtree_get_key(n), rbtree_get_data(n));
        n = rbtree_next(http->header, n);
    }
    if (http->len) {
        list_view_header *hdr;

        hdr = LV_ADD_HEADER(lw, "Data", selected[UI_SUBLAYER1], UI_SUBLAYER1);
        add_hexdump(lw, hdr, hexmode, http->data, http->len);
    }
}

void add_snmp_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct snmp_info *snmp = pdata->data;
    list_view_header *hdr;

    LV_ADD_TEXT_ELEMENT(lw, header, "Version: %d", snmp->version);
    LV_ADD_TEXT_ELEMENT(lw, header, "Community: %s", snmp->community);
    switch (snmp->pdu_type) {
    case SNMP_GET_REQUEST:
        hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "GetRequest");
        add_snmp_pdu(lw, hdr, snmp->pdu);
        break;
    case SNMP_GET_NEXT_REQUEST:
        hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "GetNextRequest");
        add_snmp_pdu(lw, hdr, snmp->pdu);
        break;
    case SNMP_SET_REQUEST:
        hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "SetRequest");
        add_snmp_pdu(lw, hdr, snmp->pdu);
        break;
    case SNMP_GET_RESPONSE:
        hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "GetResponse");;
        add_snmp_pdu(lw, hdr, snmp->pdu);
        break;
    case SNMP_TRAP:
        hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Trap");
        add_snmp_trap(lw, hdr, snmp->trap);
        break;
    default:
        break;
    }
}

void add_snmp_pdu(list_view *lw, list_view_header *header, struct snmp_pdu *pdu)
{
    char *error;

    LV_ADD_TEXT_ELEMENT(lw, header, "Request ID: %d", pdu->request_id);
    if ((error = get_snmp_error_status(pdu))) {
        LV_ADD_TEXT_ELEMENT(lw, header, "Error status: %s (%d)", error, pdu->error_status);
    } else {
        LV_ADD_TEXT_ELEMENT(lw, header, "Error status: %d", pdu->error_status);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "Error index: %d", pdu->error_index);
    add_snmp_variables(lw, header, pdu->varbind_list);
}

void add_snmp_trap(list_view *lw, list_view_header *header, struct snmp_trap *pdu)
{
    char *trap;

    LV_ADD_TEXT_ELEMENT(lw, header, "Enterprise: %s", pdu->enterprise);
    LV_ADD_TEXT_ELEMENT(lw, header, "Agent address: %s", pdu->agent_addr);
    if ((trap =get_snmp_trap_type(pdu))) {
        LV_ADD_TEXT_ELEMENT(lw, header, "Trap type: %s (%d)", trap, pdu->trap_type);
    } else {
        LV_ADD_TEXT_ELEMENT(lw, header, "Trap type: %d", pdu->trap_type);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "Specific code: %d", pdu->specific_code);
    add_snmp_variables(lw, header, pdu->varbind_list);
}

void add_snmp_variables(list_view *lw, list_view_header *header, list_t *vars)
{
    const node_t *n = list_begin(vars);

    while (n) {
        struct snmp_varbind *var = list_data(n);
        list_view_header *hdr;

        switch (var->type) {
        case SNMP_INTEGER_TAG:
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "%s: %d",
                                 var->object_name, var->object_syntax.ival);
            LV_ADD_TEXT_ELEMENT(lw, hdr, "Object name: %s", var->object_name);
            LV_ADD_TEXT_ELEMENT(lw, hdr, "Value: %d", var->object_syntax.ival);
            break;
        case SNMP_NULL_TAG:
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "%s: null",
                                 var->object_name);
            LV_ADD_TEXT_ELEMENT(lw, hdr, "Object name: %s", var->object_name);
            LV_ADD_TEXT_ELEMENT(lw, hdr, "Value: null");
            break;
        case SNMP_OCTET_STRING_TAG:
        {
            bool printable = true;
            char buf[512];

            for (unsigned int i = 0; i < var->plen; i++) {
                if (!isprint(var->object_syntax.pval[i])) {
                    printable = false;
                    break;
                }
            }
            for (unsigned int i = 0; i < var->plen; i++) {
                snprintf(buf + 2 * i, 512 - 2 * i, "%02x", (unsigned char) var->object_syntax.pval[i]);
            }
            if (printable) {
                hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "%s: %s",
                                     var->object_name, var->object_syntax.pval);
                LV_ADD_TEXT_ELEMENT(lw, hdr, "Object name: %s", var->object_name);
                LV_ADD_TEXT_ELEMENT(lw, hdr, "Value: %s (%s)", var->object_syntax.pval, buf);
            } else {
                hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "%s: %s",
                                     var->object_name, buf);
                LV_ADD_TEXT_ELEMENT(lw, hdr, "Object name: %s", var->object_name);
                LV_ADD_TEXT_ELEMENT(lw, hdr, "Value: %s", buf);
            }
            break;
        }
        case SNMP_OBJECT_ID_TAG:
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "%s: %s",
                                 var->object_name, var->object_syntax.pval);
            LV_ADD_TEXT_ELEMENT(lw, hdr, "Object name: %s", var->object_name);
            LV_ADD_TEXT_ELEMENT(lw, hdr, "Value: %s", var->object_syntax.pval);
            break;
        default:
            break;
        }
        n = list_next(n);
    }
}

void add_imap_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct imap_info *imap = pdata->data;

    if (imap->lines) {
        const node_t *n = list_begin(imap->lines);

        while (n) {
            LV_ADD_TEXT_ELEMENT(lw, header, "%s", (char *) list_data(n));
            n = list_next(n);
        }
    }
}

void add_smtp_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct smtp_info *smtp = pdata->data;

    if (smtp->data) {
        char *buf = malloc(smtp->len + 1);
        int c = 0;

        for (unsigned int i = 0; i < smtp->len; i++) {
            if (isprint(smtp->data[i]))
                buf[i] = smtp->data[i];
            else
                buf[i] = '.';
            if (smtp->data[i] == '\n') {
                buf[i + 1] = '\0';
                LV_ADD_TEXT_ELEMENT(lw, header, "%s", buf + c);
                c = i + 1;
            }
        }
        free(buf);
    } else {
        if (smtp->response) {
            char *code = get_smtp_code(smtp->rsp.code);
            const node_t *n;

            if (code)
                LV_ADD_TEXT_ELEMENT(lw, header, "Reply code %d: %s", smtp->rsp.code, code);
            else
                LV_ADD_TEXT_ELEMENT(lw, header, "Reply code %d", smtp->rsp.code);
            LIST_FOREACH(smtp->rsp.lines, n)
                LV_ADD_TEXT_ELEMENT(lw, header, "Reply parameters: %s", (char *) list_data(n));
        } else {
            if (smtp->cmd.command) {
                LV_ADD_TEXT_ELEMENT(lw, header, "Command: %s", smtp->cmd.command);
                LV_ADD_TEXT_ELEMENT(lw, header, "Parameters: %s", smtp->cmd.params);
            } else {
                LV_ADD_TEXT_ELEMENT(lw, header, "Parameters: %s", smtp->start_line);
            }
        }
    }
}

void add_dhcp_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct dhcp_info *dhcp = pdata->data;
    char *str;
    list_view_header *flag_hdr;
    char addr[INET_ADDRSTRLEN];
    char hwaddr[HW_ADDRSTRLEN];

    if ((str = get_dhcp_opcode(dhcp->op)) != NULL)
        LV_ADD_TEXT_ELEMENT(lw, header, "Message opcode: %s (%d)", str, dhcp->op);
    if ((str = get_arp_hardware_type(dhcp->htype)) != NULL)
        LV_ADD_TEXT_ELEMENT(lw, header, "Hardware address type: %s (%d)", str, dhcp->htype);
    LV_ADD_TEXT_ELEMENT(lw, header, "Hops: %d", dhcp->hops);
    LV_ADD_TEXT_ELEMENT(lw, header, "Transaction id: 0x%x", dhcp->xid);
    LV_ADD_TEXT_ELEMENT(lw, header, "Seconds elapsed: %d", dhcp->secs);
    str = (dhcp->flags == 0x8000) ? "Broadcast" : "Unicast";
    flag_hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "Flags: %s (0x%x)", str, dhcp->flags);
    add_flags(lw, flag_hdr, dhcp->flags, get_dhcp_flags(), get_dhcp_flags_size());
    inet_ntop(AF_INET, &dhcp->ciaddr, addr, INET_ADDRSTRLEN);
    LV_ADD_TEXT_ELEMENT(lw, header, "Client IP address: %s", addr);
    inet_ntop(AF_INET, &dhcp->yiaddr, addr, INET_ADDRSTRLEN);
    LV_ADD_TEXT_ELEMENT(lw, header, "Your (client) IP address: %s", addr);
    inet_ntop(AF_INET, &dhcp->siaddr, addr, INET_ADDRSTRLEN);
    LV_ADD_TEXT_ELEMENT(lw, header, "IP address of next server: %s", addr);
    inet_ntop(AF_INET, &dhcp->giaddr, addr, INET_ADDRSTRLEN);
    LV_ADD_TEXT_ELEMENT(lw, header, "Relay agent IP address: %s", addr);
    HW_ADDR_NTOP(hwaddr, dhcp->chaddr);
    LV_ADD_TEXT_ELEMENT(lw, header, "Client hardware address: %s", hwaddr);
    if (dhcp->sname[0] != '\0')
        LV_ADD_TEXT_ELEMENT(lw, header, "Server host name: %s", dhcp->sname);
    else
        LV_ADD_TEXT_ELEMENT(lw, header, "Server host name: Not given");
    if (dhcp->file[0] != '\0')
        LV_ADD_TEXT_ELEMENT(lw, header, "Boot file name: %s", dhcp->file);
    else
        LV_ADD_TEXT_ELEMENT(lw, header, "Boot file name: Not given");
    LV_ADD_TEXT_ELEMENT(lw, header, "Magic cookie: %s (0x%x)", (dhcp->magic_cookie == DHCP_COOKIE) ?
                        "DHCP" : "", dhcp->magic_cookie);
    add_dhcp_options(lw, header, dhcp);
}

static void add_dhcp_options(list_view *lw, list_view_header *header, struct dhcp_info *dhcp)
{
    const node_t *node;
    char buf[256] = { 0 };
    struct tm_t t;
    uint32_t addr;

    LIST_FOREACH(dhcp->options, node) {
        list_view_header *opthdr;
        struct dhcp_options *opt = (struct dhcp_options *) list_data(node);

        opthdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                   "Option: %s (%d)", get_dhcp_option_type(opt->tag), opt->tag);
        LV_ADD_TEXT_ELEMENT(lw, opthdr, "Length: %d", opt->length);
        switch (opt->tag) {
        case DHCP_MESSAGE_TYPE:
        case DHCP_TRAILER_ENCAPSULATION:
        case DHCP_ETHERNET_ENCAPSULATION:
        case DHCP_TCP_DEFAULT_TTL:
        case DHCP_TCP_KEEPALIVE_GARBARGE:
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Value: %s (%d)", get_dhcp_message_type(opt->byte), opt->byte);
            break;
        case DHCP_PARAMETER_REQUEST_LIST:
            for (int i = 0; i < opt->length; i++)
                LV_ADD_TEXT_ELEMENT(lw, opthdr, "Option code: %s (%d)",
                                    get_dhcp_option_type(opt->bytes[i]), opt->bytes[i]);
            break;
        case DHCP_MAXIMUM_MESSAGE_SIZE:
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Maximum DHCP message size: %d", opt->u16val);
            break;
        case DHCP_CLIENT_IDENTIFIER:
            if (opt->bytes[0] == 0) {
                for (int i = 0; i < opt->length; i++) {
                    snprintf(buf + 2 * i, 256 - 2 * i, "%02x", (unsigned char) opt->bytes[i]);
                }
            } else {
                LV_ADD_TEXT_ELEMENT(lw, opthdr, "Hardware type: %s (%d)",
                                    get_arp_hardware_type(opt->bytes[0]), opt->bytes[0]);
                opt->bytes++;
                HW_ADDR_NTOP(buf, opt->bytes);
            }
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Client Identifier: %s", buf);
            break;
        case DHCP_IP_ADDRESS_LEASE_TIME:
            t = get_time(opt->u32val);
            time_ntop(&t, buf, 256);
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Lease time: %s (%d seconds)", buf, opt->u32val);
            break;
        case DHCP_HOST_NAME:
        case DHCP_DOMAIN_NAME:
        case DHCP_NIS_DOMAIN:
        case DHCP_NISP_DOMAIN:
        case DHCP_TFTP_SERVER_NAME:
            memcpy(buf, opt->bytes, opt->length);
            buf[opt->length] = '\0';
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Name: %s", buf);
            break;
        case DHCP_SUBNET_MASK:
            addr = htonl(opt->u32val);
            inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Subnet mask: %s", buf);
            break;
        case DHCP_RENEWAL_TIME_VAL:
            t = get_time(opt->u32val);
            time_ntop(&t, buf, 256);
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "T1 interval: %s (%d seconds)", buf, opt->u32val);
            break;
        case DHCP_REBINDING_TIME_VAL:
            t = get_time(opt->u32val);
            time_ntop(&t, buf, 256);
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "T2 interval: %s (%d seconds)", buf, opt->u32val);
            break;
        case DHCP_SERVER_IDENTIFIER:
        case DHCP_REQUESTED_IP_ADDRESS:
        case DHCP_ROUTER_SOLICITATION_ADDRESS:
            addr = htonl(opt->u32val);
            inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Address: %s", buf);
            break;
        case DHCP_ROUTER:
        case DHCP_DOMAIN_NAME_SERVER:
        case DHCP_NETWORK_INFORMATION_SERVERS:
        case DHCP_NTP_SERVERS:
        case DHCP_XWINDOWS_SFS:
        case DHCP_XWINDOWS_DM:
        case DHCP_NISP_SERVERS:
        case DHCP_NETBIOS_DD:
        case DHCP_IMPRESS_SERVER:
        case DHCP_NETBIOS_NS:
        case DHCP_MOBILE_IP_HA:
        case DHCP_SMTP_SERVER:
        case DHCP_POP3_SERVER:
        case DHCP_NNTP_SERVER:
        case DHCP_WWW_SERVER:
        case DHCP_FINGER_SERVER:
        case DHCP_IRC_SERVER:
        case DHCP_STREETTALK_SERVER:
        case DHCP_STDA_SERVER:
            for (int i = 0, c = 1; i < opt->length; i += 4, c++) {
                inet_ntop(AF_INET, opt->bytes + i, buf, INET_ADDRSTRLEN);
                LV_ADD_TEXT_ELEMENT(lw, opthdr, "Address %d: %s", c, buf);
            }
            break;
        case DHCP_ARP_CACHE_TIMEOUT:
        case DHCP_TCP_KEEPALIVE_INTERVAL:
            t = get_time(opt->u32val);
            time_ntop(&t, buf, 256);
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Value: %s (%d seconds)", buf, opt->u32val);
            break;
        case DHCP_VENDOR_SPECIFIC:
        case DHCP_NETBIOS_SCOPE:
            for (int i = 0; i < opt->length; i++) {
                snprintf(buf + 2 * i, 256 - 2 * i, "%02x", (unsigned char) opt->bytes[i]);
            }
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Value: %s", buf);
            break;
        case DHCP_NETBIOS_NT:
        {
            char *type = get_dhcp_netbios_node_type(opt->byte);

            if (type)
                LV_ADD_TEXT_ELEMENT(lw, opthdr, "Node type: %s (0x%x)", type, opt->byte);
            else
                LV_ADD_TEXT_ELEMENT(lw, opthdr, "Node type: 0x%x", opt->byte);
            break;
        }
        case DHCP_OPTION_OVERLOAD:
        {
            char *type = get_dhcp_option_overload(opt->byte);

            if (type)
                LV_ADD_TEXT_ELEMENT(lw, opthdr, "Option overload: %s (0x%x)", type, opt->byte);
            else
                LV_ADD_TEXT_ELEMENT(lw, opthdr, "Option overload: 0x%x", opt->byte);
            break;
        }
        case DHCP_CLIENT_FQDN:
        {
            list_view_header *fhdr;

            fhdr = LV_ADD_SUB_HEADER(lw, opthdr, selected[UI_FLAGS], UI_FLAGS, "Flags", opt->fqdn.flags);
            add_flags(lw, fhdr, opt->fqdn.flags, get_dhcp_fqdn_flags(), get_dhcp_fqdn_flags_size());
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "RCODE1: 0x%x", opt->fqdn.rcode1);
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "RCODE2: 0x%x", opt->fqdn.rcode2);
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "name: %s", opt->fqdn.name);
            break;
        }
        case DHCP_UUID_CLIENT_ID:
            if (opt->bytes[0] == 0) { /* type 0 is UUID */
                char *uuid = uuid_format(opt->bytes + 1);

                LV_ADD_TEXT_ELEMENT(lw, opthdr, "UUID: %s", uuid);
                free(uuid);
            } else {
                for (int i = 0; i < opt->length; i++) {
                    snprintf(buf + 2 * i, 256 - 2 * i, "%02x", (unsigned char) opt->bytes[i]);
                }
                LV_ADD_TEXT_ELEMENT(lw, opthdr, "Value: %s", buf);
            }
            break;
        case DHCP_CLIENT_NDI:
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Type: %d", opt->ndi.type);
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Major version: %d", opt->ndi.maj);
            LV_ADD_TEXT_ELEMENT(lw, opthdr, "Minor version: %d", opt->ndi.min);
            break;
        case DHCP_CLIENT_SA:
        {
            char *type = get_dhcp_option_architecture(opt->byte);

            if (type)
                LV_ADD_TEXT_ELEMENT(lw, opthdr, "Client System Architecture: %s", type);
            else
                LV_ADD_TEXT_ELEMENT(lw, opthdr, "Client System Architecture: %d", opt->byte);
            break;
        }
        default:
            break;
        }
    }
}

void add_tls_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct tls_info *tls = pdata->data;
    list_view_header *record;

    while (tls) {
        if (tls->type == TLS_HANDSHAKE) {
            record = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                       "TLS Record: Handshake: %s",
                                       get_tls_handshake_type(tls->handshake->type));
        } else {
            record = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                       "TLS Record: %s", get_tls_type(tls->type));
        }
        LV_ADD_TEXT_ELEMENT(lw, record, "Type: %s", get_tls_type(tls->type));
        LV_ADD_TEXT_ELEMENT(lw, record, "Version: %s (0x%x)",
                            get_tls_version(tls->version), tls->version);
        LV_ADD_TEXT_ELEMENT(lw, record, "Length: %d", tls->length);
        switch (tls->type) {
        case TLS_HANDSHAKE:
            add_tls_handshake(lw, record, tls->handshake);
            break;
        default:
            break;
        }
        tls = tls->next;
    }
}

void add_tls_handshake(list_view *lw, list_view_header *header,
                       struct tls_handshake *handshake)
{
    list_view_header *hdr;

    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Handshake: %s",
                            get_tls_handshake_type(handshake->type));
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Type: %s", get_tls_handshake_type(handshake->type));
    if (handshake->type != ENCRYPTED_HANDSHAKE_MESSAGE) {
        LV_ADD_TEXT_ELEMENT(lw, hdr, "Length: %d", handshake->length[0] << 16 |
                            handshake->length[1] << 8 | handshake->length[2]);
        switch (handshake->type) {
        case TLS_CLIENT_HELLO:
            add_tls_client_hello(lw, hdr, handshake->client_hello);
            break;
        case TLS_SERVER_HELLO:
            add_tls_server_hello(lw, hdr, handshake->server_hello);
            break;
        default:
            break;
        }
    }
}

void add_tls_client_hello(list_view *lw, list_view_header *header,
                          struct tls_handshake_client_hello *hello)
{
    list_view_header *hdr;
    list_view_header *sub;
    char buf[65];

    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Client Hello");
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Protocol Version: %s",
                        get_tls_version(hello->legacy_version));
    for (int i = 0; i < 32; i++) {
        snprintf(buf + 2 * i, 3, "%02x", hello->random_bytes[i]);
    }
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Random bytes: %s", buf);
    for (int i = 0; i < hello->session_length; i++) {
        snprintf(buf + 2 * i, 3, "%02x", hello->session_id[i]);
    }
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Session id length: %d", hello->session_length);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Session id: %s", buf);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Cipher suite length: %d", hello->cipher_length);
    sub = LV_ADD_SUB_HEADER(lw, hdr, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Ciper Suites");
    for (int i = 0; i < hello->cipher_length / 2; i++) {
        LV_ADD_TEXT_ELEMENT(lw, sub, "%s (0x%04x)",
                            get_tls_cipher_suite(ntohs(hello->cipher_suites[i])),
                            ntohs(hello->cipher_suites[i]));
    }
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Compression length: %d", hello->compression_length);
    add_tls_extensions(lw, hdr, hello->data, hello->data_len);
}

void add_tls_server_hello(list_view *lw, list_view_header *header,
                          struct tls_handshake_server_hello *hello)
{
    list_view_header *hdr;
    char buf[65];

    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Server Hello");
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Protocol Version: %s",
                        get_tls_version(hello->legacy_version));
    for (int i = 0; i < 32; i++) {
        snprintf(buf + 2 * i, 3, "%02x", hello->random_bytes[i]);
    }
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Random bytes: %s", buf);
    for (int i = 0; i < hello->session_length; i++) {
        snprintf(buf + 2 * i, 3, "%02x", hello->session_id[i]);
    }
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Session id length: %d", hello->session_length);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Session id: %s", buf);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Cipher suite: %s",
                        get_tls_cipher_suite(ntohs(hello->cipher_suite)));
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Compression: %d", hello->compression_method);
    add_tls_extensions(lw, hdr, hello->data, hello->data_len);
}

void add_tls_extensions(list_view *lw, list_view_header *header,
                        unsigned char *data, uint16_t len)
{
    list_t *extensions;
    list_view_header *sub;

    extensions = parse_tls_extensions(data, len);
    if (extensions) {
        const node_t *n = list_begin(extensions);

        while (n) {
            struct tls_extension *ext = list_data(n);

            switch(ext->type) {
            case SUPPORTED_GROUPS:
            {
                char *group;

                sub = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                        "Extension: Supported groups");
                for (int i = 0; i < ext->supported_groups.length / 2; i++) {
                    if ((group = get_supported_group(ntohs(ext->supported_groups.named_group_list[i])))) {
                        LV_ADD_TEXT_ELEMENT(lw, sub, "%s", group);
                    }
                }
                break;
            }
            case SIGNATURE_ALGORITHMS:
            {
                char *alg;

                sub = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                        "Extension: Signature algorithms");
                for (int i = 0; i < ext->signature_algorithms.length / 2; i++) {
                    if ((alg = get_signature_scheme(ntohs(ext->signature_algorithms.types[i])))) {
                        LV_ADD_TEXT_ELEMENT(lw, sub, "%s", alg);
                    }
                }
                break;
            }
            case SUPPORTED_VERSIONS:
            {
                int len = ext->supported_versions.length;

                sub = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                        "Extension: Supported version");
                while (len > 0) {
                    LV_ADD_TEXT_ELEMENT(lw, sub, "%s",
                                        get_tls_version(*ext->supported_versions.versions));
                    len -= 2;
                }
                break;
            }
            case COOKIE:
            {
                char *buf = malloc(ext->cookie.length * 2);

                sub = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                        "Extension: Cookie");
                for (int i = 0; i < ext->cookie.length; i++) {
                    snprintf(buf + 2 * i, 3, "%02x", ext->cookie.ptr[i]);
                }
                LV_ADD_TEXT_ELEMENT(lw, sub, "%s", buf);
                free(buf);
                break;
            }
            default:
                break;
            }
            n = list_next(n);
        }
    }
    free_tls_extensions(extensions);
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
        LV_ADD_TEXT_ELEMENT(lw, header, "%s", buf);
        for (int j = 0; j < pf[i].width; j++) {
            buf[k + j] = '.';
        }
        k += pf[i].width;
    }
}
