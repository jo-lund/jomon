#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/igmp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include "print_protocol.h"
#include "decoder/decoder.h"
#include "jomon.h"
#include "decoder/host_analyzer.h"
#include "field.h"

#define HOSTNAMELEN 255 /* maximum 255 according to rfc1035 */
#define TBUFLEN 16

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define PRINT_NUMBER(buffer, n, i)                  \
    snprintf(buffer, n, "%-" STR(NUM_WIDTH) "u", i)
#define PRINT_TIME(buffer, n, t)                    \
    snprintf(buffer + NUM_WIDTH, n - NUM_WIDTH, "%-" STR(TIME_WIDTH) "s", t)
#define PRINT_ADDRESS(buffer, n, src, dst)                              \
    snprintf(buffer + NUM_WIDTH + TIME_WIDTH, n - NUM_WIDTH - TIME_WIDTH, \
             "%-" STR(ADDR_WIDTH) "s" "%-" STR(ADDR_WIDTH) "s", src, dst)
#define PRINT_PROTOCOL(buffer, n, prot)                     \
    snprintf(buffer + NUM_WIDTH + TIME_WIDTH + 2 * ADDR_WIDTH, n - NUM_WIDTH - TIME_WIDTH - 2 * ADDR_WIDTH, \
             "%-" STR(PROT_WIDTH) "s", prot)
#define PRINT_INFO(buffer, n, fmt, ...) \
    snprintcat(buffer, n, fmt, ##__VA_ARGS__)

#define PRINT_LINE(buffer, n, i, t, src, dst, prot, fmt, ...)   \
    do {                                                        \
        PRINT_NUMBER(buffer, n, i);                             \
        PRINT_TIME(buffer, n, t);                               \
        PRINT_ADDRESS(buffer, n, src, dst);                     \
        PRINT_PROTOCOL(buffer, n, prot);                        \
        PRINT_INFO(buffer, n, fmt, ## __VA_ARGS__);             \
    } while (0)


/*
 * Convert the network address 'src' into a string in 'dst', or store the
 * host name if that is available.
 */
static void get_name_or_address(const uint32_t src, char *dst)
{
    struct host_info *host;
    char *p;

    if ((host = host_get_ip4host(src)) && host->name) {
        strlcpy(dst, host->name, HOSTNAMELEN);
        if (ctx.opt.no_domain) {
            if ((p = strchr(dst, '.')))
                *p = '\0';
        }
        string_truncate(dst, HOSTNAMELEN, ADDR_WIDTH - 1);
    } else {
        inet_ntop(AF_INET, &src, dst, INET_ADDRSTRLEN);
    }
}

static void print_address(char *buf, size_t n, const struct packet *p)
{
    struct packet_data *pdata;

    pdata = p->root;
    if (pdata->next) {
        if (is_ipv4(pdata->next)) {
            char src[HOSTNAMELEN+1];
            char dst[HOSTNAMELEN+1];
            uint32_t saddr;
            uint32_t daddr;

            if (field_empty(pdata->next->data))
                return;
            saddr = ipv4_src(p);
            daddr = ipv4_dst(p);
            if (ctx.opt.numeric) {
                inet_ntop(AF_INET, &saddr, src, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &daddr, dst, INET_ADDRSTRLEN);
            } else {
                get_name_or_address(saddr, src);
                get_name_or_address(daddr, dst);
            }
            PRINT_ADDRESS(buf, n, src, dst);
            return;
        } else if (is_ipv6(pdata->next)) {
            char src[INET6_ADDRSTRLEN];
            char dst[INET6_ADDRSTRLEN];
            uint8_t *saddr;
            uint8_t *daddr;

            if (field_empty(pdata->next->data))
                return;
            saddr = field_search_value(pdata->next->data, "Source address");
            daddr = field_search_value(pdata->next->data, "Destination address");
            inet_ntop(AF_INET6, saddr, src, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, daddr, dst, INET6_ADDRSTRLEN);
            PRINT_ADDRESS(buf, n, src, dst);
            return;
        }
    }
    if (is_ethernet(pdata)) {
        if (!field_empty(pdata->data)) {
            char smac[HW_ADDRSTRLEN];
            char dmac[HW_ADDRSTRLEN];
            unsigned char *src;
            unsigned char *dst;

            src = field_search_value(pdata->data, "MAC source");
            dst = field_search_value(pdata->data, "MAC destination");
            HW_ADDR_NTOP(smac, src);
            HW_ADDR_NTOP(dmac, dst);
            PRINT_ADDRESS(buf, n, smac, dmac);
        }
    } else {
        PRINT_ADDRESS(buf, n, "N/A", "N/A");
    }
}

void pkt2text(char *buf, size_t size, const struct packet *p)
{
    struct protocol_info *pinfo;
    struct packet_data *pdata;
    char time[TBUFLEN];

    assert(p->root);
    pdata = p->root;
    pinfo = get_protocol(pdata->id);
    if (pinfo && pinfo->print_pdu) {
        format_timeval(&p->time, time, TBUFLEN);
        PRINT_NUMBER(buf, size, p->num);
        PRINT_TIME(buf, size, time);
        print_address(buf, size, p);
        while (pdata) {
            pinfo = get_protocol(pdata->id);
            if (pinfo == NULL) {
                DEBUG("Layer: 0x%x, Key: 0x%x", get_protocol_layer(pdata->id),
                      get_protocol_key(pdata->id));
                return;
            }
            if (pinfo->print_pdu && pdata->next == NULL) {
                char info[512];
                PRINT_PROTOCOL(buf, size, pinfo->short_name);
                pinfo->print_pdu(info, 512, pdata);
                PRINT_INFO(buf, size, "%s", info);
            }
            pdata = pdata->next;
        }
    } else {
        format_timeval(&p->time, time, TBUFLEN);
        PRINT_LINE(buf, size, p->num, time, "N/A", "N/A", "N/A", "Unknown data");
    }
}

#if 0
void print_igmp(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct igmp_info *igmp = pdata->data;

    char addr[INET_ADDRSTRLEN];

    PRINT_PROTOCOL(buf, n, "IGMP");
    switch (igmp->type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        PRINT_INFO(buf, n, "Membership query  Max response time: %d seconds",
                   igmp->max_resp_time / 10);
        break;
    case IGMP_v1_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "Membership report");
        break;
    case IGMP_v2_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "IGMP2 Membership report");
        break;
    case IGMP_v3_HOST_MEMBERSHIP_REPORT:
        PRINT_INFO(buf, n, "IGMP3 Membership report");
        break;
    case IGMP_HOST_LEAVE_MESSAGE:
        PRINT_INFO(buf, n, "Leave group");
        break;
    default:
        PRINT_INFO(buf, n, "Type 0x%x", igmp->type);
        break;
    }
    if (igmp->type != IGMP_v3_HOST_MEMBERSHIP_REPORT) {
        inet_ntop(AF_INET, &igmp->group_addr, addr, INET_ADDRSTRLEN);
        PRINT_INFO(buf, n, "  Group address: %s", addr);
    }
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

    if (!PACKET_HAS_DATA(pdata->next)) {
        PRINT_PROTOCOL(buf, n, "TCP");
        PRINT_INFO(buf, n, "Source port: %d  Destination port: %d",
                   tcp->sport, tcp->dport);
        PRINT_INFO(buf, n, "  Flags:");
        if (tcp->fin)
            PRINT_INFO(buf, n, " FIN");
        if (tcp->syn)
            PRINT_INFO(buf, n, " SYN");
        if (tcp->rst)
            PRINT_INFO(buf, n, " RST");
        if (tcp->psh)
            PRINT_INFO(buf, n, " PSH");
        if (tcp->ack)
            PRINT_INFO(buf, n, " ACK");
        if (tcp->urg)
            PRINT_INFO(buf, n, " URG");
        if (tcp->ece)
            PRINT_INFO(buf, n, " ECE");
        if (tcp->cwr)
            PRINT_INFO(buf, n, " CWR");
        if (tcp->ns)
            PRINT_INFO(buf, n, " NS");
        PRINT_INFO(buf, n, "  seq: %u  ack: %u  win: %u",
                   tcp->seq_num, tcp->ack_num, tcp->window);
    }
}

void print_dns(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct dns_info *dns = pdata->data;

    if (get_protocol_key(pdata->id) == DNS)
        PRINT_PROTOCOL(buf, n, "DNS");
    else if (get_protocol_key(pdata->id) == MDNS)
        PRINT_PROTOCOL(buf, n, "MDNS");
    else
        PRINT_PROTOCOL(buf, n, "LLMNR");
    if (dns->qr == 0) {
        switch (dns->opcode) {
        case DNS_QUERY:
            PRINT_INFO(buf, n, "Standard query");
            if (dns->question) {
                PRINT_INFO(buf, n, ": %s ", dns->question[0].qname);
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
        if (dns->rcode == DNS_NO_ERROR)
            PRINT_INFO(buf, n, "Response: ");
        else
            PRINT_INFO(buf, n, "Response: %s ", get_dns_rcode(dns->rcode));
        if (dns->question)
            PRINT_INFO(buf, n, "%s ", dns->question[0].qname);
        if (dns->record) {
            for (unsigned int i = 0; i < dns->section_count[ANCOUNT]; i++) {
                if (dns->record[i].type == 0)
                    continue;
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
    char opcode[16];

    PRINT_PROTOCOL(buf, n, "NBNS");
    if (nbns->r == 0) {
        strlcpy(opcode, get_nbns_opcode(nbns->opcode), sizeof(opcode));
        PRINT_INFO(buf, n, "Name %s request: ", string_tolower(opcode));
        PRINT_INFO(buf, n, "%s  ", nbns->question.qname);
        PRINT_INFO(buf, n, "%s  ", get_nbns_type(nbns->question.qtype));
        if (nbns->section_count[ARCOUNT] && nbns->record) {
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
        strlcpy(opcode, get_nbns_opcode(nbns->opcode), sizeof(opcode));
        PRINT_INFO(buf, n, "Name %s response: ", string_tolower(opcode));
        if (nbns->record) {
            PRINT_INFO(buf, n, "%s  ", nbns->record[0].rrname);
            PRINT_INFO(buf, n, "%s  ", get_nbns_type(nbns->record[0].rrtype));
            print_nbns_record(nbns, 0, buf, n);
        }
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
        PRINT_INFO(buf, n, "%s", (char *) list_data(node));
    }
}

void print_http(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct http_info *http = pdata->data;

    PRINT_PROTOCOL(buf, n, "HTTP");
    if (http->start_line)
        PRINT_INFO(buf, n, "%s", http->start_line);
    else
        PRINT_INFO(buf, n, "Data");
}

void print_imap(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct imap_info *imap = pdata->data;

    PRINT_PROTOCOL(buf, n, "IMAP");
    if (imap->lines && list_size(imap->lines) > 0)
        PRINT_INFO(buf, n, "%s", (char *) list_front(imap->lines));
}

void print_smtp(char *buf, int n, void *data)
{
    struct packet_data *pdata = data;
    struct smtp_info *smtp = pdata->data;

    PRINT_PROTOCOL(buf, n, "SMTP");
    if (smtp->data) {
        PRINT_INFO(buf, n, "C: Mail data");
    } else {
        if (smtp->response && smtp->rsps) {
            const node_t *node;
            struct smtp_rsp *rsp;

            PRINT_INFO(buf, n, "S: ");
            DLIST_FOREACH(smtp->rsps, node) {
                const node_t *line;

                rsp = list_data(node);
                PRINT_INFO(buf, n, "%d%c", rsp->code, list_size(rsp->lines) > 1 ? '-' : ' ');
                DLIST_FOREACH(rsp->lines, line) {
                    PRINT_INFO(buf, n, "%s  ", (char *) list_data(line));
                }
            }
        } else if (smtp->cmds) {
            const node_t *node;
            struct smtp_cmd *cmd;

            PRINT_INFO(buf, n, "C: ");
            DLIST_FOREACH(smtp->cmds, node) {
                cmd = list_data(node);
                PRINT_INFO(buf, n, "%s %s  ", cmd->command, cmd->params);
            }
        }
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
    if (tls->type == TLS_HANDSHAKE && tls->handshake) {
        snprintf(records, MAXLINE, "%s", get_tls_handshake_type(tls->handshake->type));
    } else {
        snprintf(records, MAXLINE, "%s", type);
    }
    tls = tls->next;
    while (tls) {
        if (tls->type == TLS_HANDSHAKE && tls->handshake) {
            snprintcat(records, MAXLINE, ", %s", get_tls_handshake_type(tls->handshake->type));
        } else {
            snprintcat(records, MAXLINE, ", %s", get_tls_type(tls->type));
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
    DLIST_FOREACH(dhcp->options, node) {
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
    if (!snmp->trap && !snmp->pdu)
        return;
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

void print_vrrp(char *buf, int n, void *data)
{
    struct vrrp_info *vrrp;
    char *type;

    vrrp = ((struct packet_data *) data)->data;
    PRINT_PROTOCOL(buf, n, "VRRP");
    if ((type = get_vrrp_type(vrrp->type))) {
        if (vrrp->version < 3)
            PRINT_INFO(buf, n, "%s  Version: %u  VRID: %u  Priority: %u  Time interval: %u",
                       type, vrrp->version, vrrp->vrid, vrrp->priority, vrrp->v.advr_int);
        else if (vrrp->version == 3)
            PRINT_INFO(buf, n, "Type: %d  Version: %u  VRID: %u  Priority: %u  Time interval:> %u",
                       vrrp->type, vrrp->version, vrrp->vrid, vrrp->priority, vrrp->v3.max_advr_int);
    }
}

void print_dns_record(struct dns_info *info, int i, char *buf, int n, uint16_t type)
{
    switch (type) {
    case DNS_TYPE_A:
        if (info->record[i].rdata.address) {
            char addr[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, (struct in_addr *) &info->record[i].rdata.address, addr, sizeof(addr));
            snprintcat(buf, n, "%s", addr);
        }
        break;
    case DNS_TYPE_NS:
        if (info->record[i].rdata.nsdname[0])
            snprintcat(buf, n, "%s", info->record[i].rdata.nsdname);
        break;
    case DNS_TYPE_CNAME:
        if (info->record[i].rdata.cname[0])
            snprintcat(buf, n, "%s", info->record[i].rdata.cname);
        break;
    case DNS_TYPE_PTR:
        if (info->record[i].rdata.ptrdname[0])
            snprintcat(buf, n, "%s", info->record[i].rdata.ptrdname);
        break;
    case DNS_TYPE_AAAA:
    {
        static char addr[INET6_ADDRSTRLEN];

        if (memcmp(info->record[i].rdata.ipv6addr, addr, 16)) {
            inet_ntop(AF_INET6, (struct in_addr *) info->record[i].rdata.ipv6addr, addr, sizeof(addr));
            snprintcat(buf, n, "%s", addr);
        }
        break;
    }
    case DNS_TYPE_HINFO:
        if (info->record[i].rdata.hinfo.cpu && info->record[i].rdata.hinfo.os) {
            snprintcat(buf, n, "%s ", info->record[i].rdata.hinfo.cpu);
            snprintcat(buf, n, "%s", info->record[i].rdata.hinfo.os);
        }
        break;
    case DNS_TYPE_MX:
        if (info->record[i].rdata.mx.exchange[0])
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
            snprintcat(buf, n, "Group NetBIOS name");
        } else {
            snprintcat(buf, n, "Unique NetBIOS name");
        }
        snprintcat(buf, n, "  %s", get_nbns_node_type(info->record[i].rdata.nb.ont));
        for (int j = 0; j < info->record[i].rdata.nb.num_addr; j++) {
            char addr[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, info->record[i].rdata.nb.address + j, addr, INET_ADDRSTRLEN);
            snprintcat(buf, n, "  %s", addr);
        }
        break;
    }
    case NBNS_NS:
        snprintcat(buf, n, "  NSD Name: %s", info->record[i].rdata.nsdname);
        break;
    case NBNS_A:
    {
        char addr[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, (struct in_addr *) &info->record[i].rdata.nsdipaddr, addr, sizeof(addr));
        snprintcat(buf, n, "  NSD IP address: %s", addr);
        break;
    }
    case NBNS_NBSTAT:
        break;
    default:
        break;
    }
}

#endif
