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
#include "layout.h"
#include "hexdump.h"
#include "geoip.h"
#include "decoder/decoder.h"
#include "jomon.h"
#include "list_view.h"
#include "ui/print_protocol.h"

extern int hexmode;
// TEMP
extern void add_flags(list_view *lw, list_view_header *header, uint32_t flags,
                      struct packet_flags *pf, int num_flags);

static void add_ipv4_options(struct ipv4_info *ip, list_view *lw, list_view_header *hdr)
{
    struct ipv4_options *opt;
    list_view_header *opt_hdr;
    int nelem;
    char time[32];
    char addr[INET_ADDRSTRLEN];

    opt_hdr = LV_ADD_SUB_HEADER(lw, hdr, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Options");
    opt = ip->opt;
    while (opt) {
        list_view_header *sub, *type_hdr;

        sub = LV_ADD_SUB_HEADER(lw, opt_hdr, selected[UI_SUBLAYER2], UI_SUBLAYER2, "%s",
                                get_ipv4_opt_type(opt->type));
        type_hdr = LV_ADD_SUB_HEADER(lw, sub, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Type: %u", opt->type);
        add_flags(lw, type_hdr, opt->type, get_ipv4_opt_flags(), get_ipv4_opt_flags_size());
        LV_ADD_TEXT_ELEMENT(lw, sub, "Length: %u", opt->length);
        switch (GET_IP_OPTION_NUMBER(opt->type)) {
        case IP_OPT_SECURITY:
            LV_ADD_TEXT_ELEMENT(lw, sub, "Security: %s", get_ipv4_security(opt->security.security));
            LV_ADD_TEXT_ELEMENT(lw, sub, "Compartments: %d", opt->security.compartments);
            LV_ADD_TEXT_ELEMENT(lw, sub, "Handling restrictions: 0x%x", opt->security.restrictions);
            break;
        case IP_OPT_LSR:
        case IP_OPT_RR:
        case IP_OPT_SSR:
            nelem = (opt->length - 3) / 4;
            for (int i = 0; i < nelem; i++) {
                inet_ntop(AF_INET, ip->opt->route.route_data + i, addr, INET_ADDRSTRLEN);
                LV_ADD_TEXT_ELEMENT(lw, sub, "Route data %d: %s", i + 1, addr);
            }
            break;
        case IP_OPT_TIMESTAMP:
            LV_ADD_TEXT_ELEMENT(lw, sub, "Pointer: %d", opt->timestamp.pointer);
            LV_ADD_TEXT_ELEMENT(lw, sub, "Overflow: %d", opt->timestamp.oflw);
            LV_ADD_TEXT_ELEMENT(lw, sub, "Flags: %d", opt->timestamp.flg);
            switch (opt->timestamp.flg) {
            case IP_TS_ONLY:
                nelem = (opt->length - 4) / 4;
                for (int i = 0; i < nelem; i++) {
                    if (IP_STANDARD_TS(*opt->timestamp.ts.timestamp))
                        LV_ADD_TEXT_ELEMENT(lw, sub, "Timestamp: %s",
                                            get_time_from_ms_ut(*opt->timestamp.ts.timestamp, time, 32));
                    else
                        LV_ADD_TEXT_ELEMENT(lw, sub, "Timestamp: %d", *opt->timestamp.ts.timestamp);
                }
                break;
            case IP_TS_ADDR:
            case IP_TS_PRESPECIFIED:
                nelem = (opt->length - 4) / 8;
                for (int i = 0; i < nelem; i++) {
                    if (IP_STANDARD_TS(*opt->timestamp.ts.timestamp))
                        LV_ADD_TEXT_ELEMENT(lw, sub, "Timestamp %d: %s", i + 1,
                                            get_time_from_ms_ut(opt->timestamp.ts.timestamp[i], time, 32));
                    else
                        LV_ADD_TEXT_ELEMENT(lw, sub, "Timestamp %d: %d", i + 1, opt->timestamp.ts.timestamp[i]);
                    inet_ntop(AF_INET, opt->timestamp.ts.addr + i, addr, INET_ADDRSTRLEN);
                    LV_ADD_TEXT_ELEMENT(lw, sub, "Address %d: %s", i + 1, addr);
                }
                break;
            default:
                break;
            }
            break;
        case IP_OPT_STREAM_ID:
            LV_ADD_TEXT_ELEMENT(lw, sub, "Stream ID: %d", opt->stream_id);
            break;
        case IP_OPT_ROUTER_ALERT:
            LV_ADD_TEXT_ELEMENT(lw, sub, "%s (%d)", get_router_alert_option(opt->router_alert),
                                opt->router_alert);
            break;
        default:
            break;
        }
        opt = opt->next;
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
    if ((dscp = get_ipv4_dscp(ip->dscp))) {
        snprintcat(buf, MAXLINE, " %s", dscp);
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "%s", buf);
    snprintf(buf, MAXLINE, "Explicit Congestion Notification (ECN): 0x%x", ip->ecn);
    if (ip->ecn == 0x3) {
        snprintcat(buf, MAXLINE, " CE");
    } else if (ip->ecn == 0x1) {
        snprintcat(buf, MAXLINE, " ECT(1)");
    } else if (ip->ecn == 0x2) {
        snprintcat(buf, MAXLINE, " ECT(0)");
    } else {
        snprintcat(buf, MAXLINE, " Not ECN-Capable");
    }
    LV_ADD_TEXT_ELEMENT(lw, header, "%s", buf);
    LV_ADD_TEXT_ELEMENT(lw, header, "Total length: %u", ip->length);
    LV_ADD_TEXT_ELEMENT(lw, header, "Identification: 0x%x (%u)", ip->id, ip->id);
    snprintf(buf, MAXLINE, "Flags: ");
    if (ip->foffset & 0x4000 || ip->foffset & 0x2000) {
        if (ip->foffset & 0x4000)
            snprintcat(buf, MAXLINE, "Don't Fragment ");
        if (ip->foffset & 0x2000)
            snprintcat(buf, MAXLINE, "More Fragments ");
    }
    snprintcat(buf, MAXLINE, "(0x%x)", flags);
    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "%s", buf);
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
    if (ctx.nogeoip) {
        LV_ADD_TEXT_ELEMENT(lw, header,"Source IP address: %s", src);
        LV_ADD_TEXT_ELEMENT(lw, header,"Destination IP address: %s", dst);
    } else {
        char buf[MAXLINE];

        LV_ADD_TEXT_ELEMENT(lw, header,"Source IP address: %s (GeoIP: %s)",
                            src, geoip_get_location(src, buf, MAXLINE));
        LV_ADD_TEXT_ELEMENT(lw, header,"Destination IP address: %s (GeoIP: %s)",
                         dst, geoip_get_location(dst, buf, MAXLINE));
    }
    if (ip->ihl > 5 && ip->opt)
        add_ipv4_options(ip, lw, header);
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
    list_view_header *data_hdr;

    LV_ADD_TEXT_ELEMENT(lw, header, "Type: %d (%s)", icmp->type, get_icmp_type(icmp->type));
    switch (icmp->type) {
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
        LV_ADD_TEXT_ELEMENT(lw, header, "Identifier: 0x%x", icmp->id);
        LV_ADD_TEXT_ELEMENT(lw, header, "Sequence number: %d", icmp->seq_num);
        if (icmp->echo.data) {
            data_hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Data");
            add_hexdump(lw, data_hdr, hexmode, icmp->echo.data, icmp->echo.len);
        }
        break;
    case ICMP_UNREACH:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d (%s)", icmp->code, get_icmp_dest_unreach_code(icmp->code));
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        break;
    case ICMP_REDIRECT:
        inet_ntop(AF_INET, &icmp->gateway, addr, INET_ADDRSTRLEN);
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d (%s)", icmp->code, get_icmp_redirect_code(icmp->code));
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Gateway: %s", addr);
        break;
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Identifier: 0x%x", icmp->id);
        LV_ADD_TEXT_ELEMENT(lw, header, "Sequence number: %d", icmp->seq_num);
        LV_ADD_TEXT_ELEMENT(lw, header, "Originate timestamp: %s",
                         get_time_from_ms_ut(icmp->timestamp.originate, time, 32));
        LV_ADD_TEXT_ELEMENT(lw, header, "Receive timestamp: %s",
                         get_time_from_ms_ut(icmp->timestamp.receive, time, 32));
        LV_ADD_TEXT_ELEMENT(lw, header, "Tramsmit timestamp: %s",
                         get_time_from_ms_ut(icmp->timestamp.transmit, time, 32));
        break;
    case ICMP_MASKREQ:
    case ICMP_MASKREPLY:
        inet_ntop(AF_INET, &icmp->addr_mask, addr, INET_ADDRSTRLEN);
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Identifier: 0x%x", icmp->id);
        LV_ADD_TEXT_ELEMENT(lw, header, "Sequence number: %d", icmp->seq_num);
        LV_ADD_TEXT_ELEMENT(lw, header, "Address mask: %s", addr);
        break;
    case ICMP_INFO_REQUEST:
    case ICMP_INFO_REPLY:
        LV_ADD_TEXT_ELEMENT(lw, header, "Identifier: 0x%x", icmp->id);
        LV_ADD_TEXT_ELEMENT(lw, header, "Sequence number: %d", icmp->seq_num);
        break;
    default:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", icmp->checksum);
        break;
    }
}

static void add_icmp6_options(list_view *lw, list_view_header *header, struct icmp6_info *icmp6)
{
    struct icmp6_option *opt;
    char link[HW_ADDRSTRLEN];
    uint8_t flags;
    list_view_header *flag_hdr, *opt_hdr;
    struct tm_t tm;
    char addr[INET6_ADDRSTRLEN];

    opt = icmp6->option;
    while (opt) {
        switch (opt->type) {
        case ND_OPT_SOURCE_LINKADDR:
            HW_ADDR_NTOP(link, opt->source_addr);
            opt_hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                        "Source link-layer address: %s", link);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Type: %d", opt->type);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Length: %d (%d bytes)", opt->length, opt->length * 8);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Link-layer address: %s", link);
            break;
        case ND_OPT_TARGET_LINKADDR:
            HW_ADDR_NTOP(link, opt->target_addr);
            opt_hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                        "Target link-layer address: %s", link);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Type: %d", opt->type);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Length: %d (%d bytes)", opt->length, opt->length * 8);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Link-layer address: %s", link);
            break;
        case ND_OPT_PREFIX_INFORMATION:
            opt_hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                        "Prefix information");
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Type: %d", opt->type);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Length: %d (%d bytes)", opt->length, opt->length * 8);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Prefix length: %d", opt->prefix_info.prefix_length);
            flags = opt->prefix_info.l << 7 | opt->prefix_info.a << 6;
            flag_hdr = LV_ADD_SUB_HEADER(lw, opt_hdr, selected[UI_FLAGS], UI_FLAGS, "Flags: 0x%x", flags);
            add_flags(lw, flag_hdr, flags, get_icmp6_prefix_flags(), get_icmp6_prefix_flags_size());
            if (opt->prefix_info.valid_lifetime == ~0U) {
                LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Valid lifetime: Infinite");
            } else {
                char buf[512];

                tm = get_time(opt->prefix_info.valid_lifetime);
                time_ntop(&tm, buf, 512);
                LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Valid lifetime: %s", buf);
            }
            if (opt->prefix_info.pref_lifetime == ~0U) {
                LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Preferred lifetime: Infinite");
            } else {
                char buf[512];

                tm = get_time(opt->prefix_info.pref_lifetime);
                time_ntop(&tm, buf, 512);
                LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Preferred lifetime: %s", buf);
            }
            inet_ntop(AF_INET6, (struct in_addr *) opt->prefix_info.prefix, addr, sizeof(addr));
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Prefix: %s", addr);
            break;
        case ND_OPT_REDIRECTED_HEADER:
            opt_hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                        "Redirect header");
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Type: %d", opt->type);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Length: %d (%d bytes)", opt->length, opt->length * 8);
            // Add ip
            break;
        case ND_OPT_MTU:
            opt_hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                        "MTU: %d", opt->mtu);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Type: %d", opt->type);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Length: %d (%d bytes)", opt->length, opt->length * 8);
            LV_ADD_TEXT_ELEMENT(lw, opt_hdr, "Recommended MTU for the link: %d", opt->mtu);
            break;
        default:
            break;
        }
        opt = opt->next;
    }
}

void add_icmp6_information(void *w, void *sw, void *data)
{
    list_view *lw = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct icmp6_info *icmp6 = pdata->data;
    char buf[1024];
    uint32_t flags;
    list_view_header *flag_hdr;
    struct tm_t tm;
    char addr[INET6_ADDRSTRLEN];

    LV_ADD_TEXT_ELEMENT(lw, header, "Type: %d (%s)", icmp6->type, get_icmp6_type(icmp6->type));
    switch (icmp6->type) {
    case ICMP6_DST_UNREACH:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d (%s)", icmp6->code, get_icmp6_dest_unreach(icmp6->code));
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: 0x%x", icmp6->checksum);
        break;
    case ICMP6_PACKET_TOO_BIG:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp6->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: 0x%x", icmp6->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Maximum transmission unit of next-hop link: %d", icmp6->code);
        break;
    case ICMP6_TIME_EXCEEDED:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d (%s)", icmp6->code, get_icmp6_time_exceeded(icmp6->code));
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: 0x%x", icmp6->checksum);
        break;
    case ICMP6_PARAM_PROB:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d (%s)", icmp6->code, get_icmp6_parameter_problem(icmp6->code));
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: 0x%x", icmp6->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Pointer: 0x%x", icmp6->pointer);
        break;
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp6->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: 0x%x", icmp6->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Identifier: 0x%x", icmp6->echo.id);
        LV_ADD_TEXT_ELEMENT(lw, header, "Sequence number: %d", icmp6->echo.seq);
        if (icmp6->echo.data) {
            for (unsigned int i = 0; i < icmp6->echo.len; i++)
                snprintf(buf + 2 * i, 1024 - 2 * i, "%02x", icmp6->echo.data[i]);
        }
        break;
    case ND_ROUTER_SOLICIT:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp6->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: 0x%x", icmp6->checksum);
        if (icmp6->option)
            add_icmp6_options(lw, header, icmp6);
        break;
    case ND_ROUTER_ADVERT:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp6->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: 0x%x", icmp6->checksum);
        LV_ADD_TEXT_ELEMENT(lw, header, "Cur Hop Limit: %d", icmp6->router_adv.cur_hop_limit);
        flags = icmp6->router_adv.m << 7 | icmp6->router_adv.o << 6;
        flag_hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "Flags: 0x%x", flags);
        add_flags(lw, flag_hdr, flags, get_icmp6_router_adv_flags(), get_icmp6_router_adv_flags_size());
        tm = get_time(icmp6->router_adv.router_lifetime);
        time_ntop(&tm, buf, 1024);
        LV_ADD_TEXT_ELEMENT(lw, header, "Router lifetime: %s", buf);
        get_time_from_ms_ut(icmp6->router_adv.reachable_time, buf, 1024);
        LV_ADD_TEXT_ELEMENT(lw, header, "Reachable time: %s", buf);
        get_time_from_ms_ut(icmp6->router_adv.retrans_timer, buf, 1024);
        LV_ADD_TEXT_ELEMENT(lw, header, "Retrans timer: %s", buf);
        if (icmp6->option)
            add_icmp6_options(lw, header, icmp6);
        break;
    case ND_NEIGHBOR_SOLICIT:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp6->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: 0x%x", icmp6->checksum);
        inet_ntop(AF_INET6, (struct in_addr *) icmp6->target_addr, addr, sizeof(addr));
        LV_ADD_TEXT_ELEMENT(lw, header, "Target address: %s", addr);
        if (icmp6->option)
            add_icmp6_options(lw, header, icmp6);
        break;
    case ND_NEIGHBOR_ADVERT:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp6->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: 0x%x", icmp6->checksum);
        flags = icmp6->neigh_adv.r << 31 | icmp6->neigh_adv.s << 30 | icmp6->neigh_adv.o << 29;
        flag_hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS,
                                     "Flags: 0x%x", flags);
        add_flags(lw, flag_hdr, flags, get_icmp6_neigh_adv_flags(),
                  get_icmp6_neigh_adv_flags_size());
        inet_ntop(AF_INET6, (struct in_addr *) icmp6->neigh_adv.target_addr, addr, sizeof(addr));
        LV_ADD_TEXT_ELEMENT(lw, header, "Target address: %s", addr);
        if (icmp6->option)
            add_icmp6_options(lw, header, icmp6);
        break;
    case ND_REDIRECT:
        LV_ADD_TEXT_ELEMENT(lw, header, "Code: %d", icmp6->code);
        LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: 0x%x", icmp6->checksum);
        inet_ntop(AF_INET6, (struct in_addr *) icmp6->redirect.target_addr, addr, sizeof(addr));
        LV_ADD_TEXT_ELEMENT(lw, header, "Target address: %s", addr);
        inet_ntop(AF_INET6, (struct in_addr *) icmp6->redirect.dest_addr, addr, sizeof(addr));
        LV_ADD_TEXT_ELEMENT(lw, header, "Destination address: %s", addr);
        if (icmp6->option)
            add_icmp6_options(lw, header, icmp6);
        break;
    default:
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
    list_view_header *flags;

    inet_ntop(AF_INET, &igmp->group_addr, addr, INET_ADDRSTRLEN);
    snprintf(buf, MAXLINE, "Type: 0x%x", igmp->type);
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
    if (igmp->type == IGMP_v3_HOST_MEMBERSHIP_REPORT)
        LV_ADD_TEXT_ELEMENT(lw, header, "Reserved: %d", igmp->max_resp_time);
    else
        LV_ADD_TEXT_ELEMENT(lw, header, "Max response time: %d seconds", igmp->max_resp_time / 10);
    LV_ADD_TEXT_ELEMENT(lw, header, "Checksum: %d", igmp->checksum);
    if (igmp->type == IGMP_v3_HOST_MEMBERSHIP_REPORT)
        LV_ADD_TEXT_ELEMENT(lw, header, "Number of group records: %d", igmp->ngroups);
    else
        LV_ADD_TEXT_ELEMENT(lw, header, "Group address: %s", addr);
    switch (igmp->type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        if (!igmp->query)
            return;
        flags = LV_ADD_SUB_HEADER(lw, header, selected[UI_FLAGS], UI_FLAGS, "Flags 0x%x",
                                  igmp->query->flags);
        add_flags(lw, flags, igmp->query->flags, get_igmp_query_flags(),
                  get_igmp_query_flags_size());
        LV_ADD_TEXT_ELEMENT(lw, header, "QQIC: %d", igmp->query->qqic);
        LV_ADD_TEXT_ELEMENT(lw, header, "Number of sources: %d", igmp->query->nsources);
        for (int i = 0; i < igmp->query->nsources && igmp->query->src_addrs; i++) {
            inet_ntop(AF_INET, igmp->query->src_addrs + i, addr, INET_ADDRSTRLEN);
            LV_ADD_TEXT_ELEMENT(lw, header, "Source address %d: %s", i + 1, addr);
        }
        break;
    case IGMP_v3_HOST_MEMBERSHIP_REPORT:
        if (!igmp->records)
            return;

        for (int i = 0; i < igmp->ngroups; i++) {
            list_view_header *group;
            char *rtype;

            group = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Group %d", i + 1);
            if ((rtype = get_igmp_group_record_type(igmp->records[i].type)))
                LV_ADD_TEXT_ELEMENT(lw, group, "Record type: %s (%d)", rtype, igmp->records[i].type);
            else
                LV_ADD_TEXT_ELEMENT(lw, group, "Record type: %d", igmp->records[i].type);
            LV_ADD_TEXT_ELEMENT(lw, group, "Aux data length: %d", igmp->records[i].aux_data_len);
            LV_ADD_TEXT_ELEMENT(lw, group, "Number of sources: %d", igmp->records[i].nsources);
            inet_ntop(AF_INET, &igmp->records[i].mcast_addr, addr, INET_ADDRSTRLEN);
            LV_ADD_TEXT_ELEMENT(lw, group, "Multicast address: %s", addr);
            for (int j = 0; j < igmp->records[i].nsources && igmp->records[i].src_addrs; j++) {
                inet_ntop(AF_INET, igmp->records[i].src_addrs + j, addr, INET_ADDRSTRLEN);
                LV_ADD_TEXT_ELEMENT(lw, group, "Source address %d: %s", j + 1, addr);
            }
        }
    default:
        break;
    }
}

static void add_pim_hello(list_view *lw, list_view_header *header, struct pim_info *pim)
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
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Holdtime: %s", time);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        case PIM_LAN_PRUNE_DELAY:
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "LAN Prune Delay");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            LV_ADD_TEXT_ELEMENT(lw, w, "Propagation delay: %u ms", hello->lan_prune_delay.prop_delay);
            LV_ADD_TEXT_ELEMENT(lw, w, "Override interval: %u ms", hello->lan_prune_delay.override_interval);
            break;
        case PIM_DR_PRIORITY:
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "DR Priority: %u", hello->dr_priority);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        case PIM_GENERATION_ID:
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Generation ID: %u", hello->gen_id);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        case PIM_STATE_REFRESH_CAPABLE:
            memset(&time, 0, 512);
            tm = get_time(hello->state_refresh.interval);
            time_ntop(&tm, time, 512);
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "State Refresh Capable");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            LV_ADD_TEXT_ELEMENT(lw, w, "Version: %u", hello->state_refresh.version);
            LV_ADD_TEXT_ELEMENT(lw, w, "Interval: %s", time);
            break;
        case PIM_ADDRESS_LIST:
        default:
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Unknown option: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option type: %u", hello->option_type);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", hello->option_len);
            break;
        }
        n = list_next(n);
    }
    list_free(opt, free);
}

static void add_pim_register(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Register Message");

    LV_ADD_TEXT_ELEMENT(lw, h, "Border bit: %d", pim->reg->border);
    LV_ADD_TEXT_ELEMENT(lw, h, "Null-Register bit: %d", pim->reg->null);
    if (pim->reg->data) {
        list_view_header *w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Data");

        add_hexdump(lw, w, hexmode, pim->reg->data, pim->reg->data_len);
    }
}

static void add_pim_register_stop(list_view *lw, list_view_header *header, struct pim_info *pim)
{
    list_view_header *h;
    char *addr;

    h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Register-Stop Message");
    addr = get_pim_address(pim->reg_stop->gaddr.addr_family, &pim->reg_stop->gaddr.addr);
    if (addr) {
        LV_ADD_TEXT_ELEMENT(lw, h, "Group address: %s/%d", addr, pim->reg_stop->gaddr.mask_len);
        free(addr);
    }
    addr = get_pim_address(pim->reg_stop->saddr.addr_family, &pim->reg_stop->saddr.addr);
    if (addr) {
        LV_ADD_TEXT_ELEMENT(lw, h, "Source address: %s", addr);
        free(addr);
    }
}

static void add_pim_assert(list_view *lw, list_view_header *header, struct pim_info *pim)
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

static void add_pim_join_prune(list_view *lw, list_view_header *header, struct pim_info *pim)
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
    grp = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Groups (%d)", pim->jpg->num_groups);
    if (!pim->jpg->groups)
        return;
    for (int i = 0; i < pim->jpg->num_groups; i++) {
        list_view_header *joined;
        list_view_header *pruned;

        addr = get_pim_address(pim->jpg->groups[i].gaddr.addr_family, &pim->jpg->groups[i].gaddr.addr);
        if (addr) {
            LV_ADD_TEXT_ELEMENT(lw, grp, "Group address %d: %s/%d", i + 1, addr, pim->jpg->groups[i].gaddr.mask_len);
            free(addr);
        }
        joined = LV_ADD_SUB_HEADER(lw, grp, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Joined sources (%d)",
                                   pim->jpg->groups[i].num_joined_src);
        for (int j = 0; j < pim->jpg->groups[i].num_joined_src && pim->jpg->groups[i].joined_src; j++) {
            addr = get_pim_address(pim->jpg->groups[i].joined_src[j].addr_family,
                                   &pim->jpg->groups[i].joined_src[j].addr);
            if (addr) {
                LV_ADD_TEXT_ELEMENT(lw, joined, "Joined address %d: %s/%d", j + 1, addr,
                                    pim->jpg->groups[i].joined_src[j].mask_len);
                free(addr);
            }
        }
        pruned = LV_ADD_SUB_HEADER(lw, grp, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Pruned sources (%d)",
                                pim->jpg->groups[i].num_pruned_src);
        for (int j = 0; j < pim->jpg->groups[i].num_pruned_src && pim->jpg->groups[i].pruned_src; j++) {
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

static void add_pim_bootstrap(list_view *lw, list_view_header *header, struct pim_info *pim)
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
    if (!pim->bootstrap->groups)
        return;
    addr = get_pim_address(pim->bootstrap->groups->gaddr.addr_family, &pim->bootstrap->groups->gaddr.addr);
    if (addr) {
        grp = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Group %s/%d",
                                addr, pim->bootstrap->groups->gaddr.mask_len);
        LV_ADD_TEXT_ELEMENT(lw, grp, "RP count: %u", pim->bootstrap->groups->rp_count);
        LV_ADD_TEXT_ELEMENT(lw, grp, "Frag RP count: %u", pim->bootstrap->groups->frag_rp_count);
        if (!pim->bootstrap->groups->rps) {
            free(addr);
            return;
        }
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

static void add_pim_candidate(list_view *lw, list_view_header *header, struct pim_info *pim)
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
    if (!pim->candidate->gaddrs)
        return;
    for (int i = 0; i < pim->candidate->prefix_count; i++) {
        addr = get_pim_address(pim->candidate->gaddrs[i].addr_family, &pim->candidate->gaddrs[i].addr);
        if (addr) {
            LV_ADD_TEXT_ELEMENT(lw, h, "Group address %d: %s/%d", i, addr, pim->candidate->gaddrs[i].mask_len);
            free(addr);
        }
    }
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
        if (pim->hello)
            add_pim_hello(lw, header, pim);
        break;
    case PIM_REGISTER:
        if (pim->reg)
            add_pim_register(lw, header, pim);
        break;
    case PIM_REGISTER_STOP:
        if (pim->reg_stop)
            add_pim_register_stop(lw, header, pim);
        break;
    case PIM_ASSERT:
        if (pim->assert)
            add_pim_assert(lw, header, pim);
        break;
    case PIM_JOIN_PRUNE:
    case PIM_GRAFT:
    case PIM_GRAFT_ACK:
        if (pim->jpg)
            add_pim_join_prune(lw, header, pim);
        break;
    case PIM_BOOTSTRAP:
        add_pim_bootstrap(lw, header, pim);
        break;
    case PIM_CANDIDATE_RP_ADVERTISEMENT:
        if (pim->candidate)
            add_pim_candidate(lw, header, pim);
        break;
    default:
        break;
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

static void add_tcp_options(list_view *lw, list_view_header *header, struct tcp *tcp)
{
    list_view_header *h;
    struct tcp_options *opt = tcp->opt;

    h = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Options");
    while (opt) {
        list_view_header *w;

        switch (opt->option_kind) {
        case TCP_OPT_NOP:
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "No operation");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_MSS:
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2,
                                  "Maximum segment size: %u", opt->mss);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_WIN_SCALE:
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2,
                                  "Window scale: %u", opt->win_scale);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_SAP:
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2,
                                  "Selective Acknowledgement permitted");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            break;
        case TCP_OPT_SACK:
        {
            const node_t *n = list_begin(opt->sack);

            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2,
                                  "Selective Acknowledgement");
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
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Timestamp");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            LV_ADD_TEXT_ELEMENT(lw, w, "Timestamp value: %u", opt->ts.ts_val);
            LV_ADD_TEXT_ELEMENT(lw, w, "Timestamp echo reply: %u", opt->ts.ts_ecr);
            break;
        case TCP_OPT_TFO:
            w = LV_ADD_SUB_HEADER(lw, h, selected[UI_SUBLAYER2], UI_SUBLAYER2, "TCP Fast Open");
            LV_ADD_TEXT_ELEMENT(lw, w, "Option kind: %u", opt->option_kind);
            LV_ADD_TEXT_ELEMENT(lw, w, "Option length: %u", opt->option_length);
            if (opt->cookie) {
                char buf[33];

                for (int i = 0; i < opt->option_length - 2; i++)
                    snprintf(buf + 2 * i, 33 - 2 * i, "%02x", opt->cookie[i]);
                LV_ADD_TEXT_ELEMENT(lw, w, "Fast Open cookie: %s", buf);
            } else {
                LV_ADD_TEXT_ELEMENT(lw, w, "Fast Open cookie request");
            }
        default:
            break;
        }
        opt = opt->next;
    }
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
    if (tcp->opt)
        add_tcp_options(lw, header, tcp);
}

static void add_dns_txt(list_view *lw, list_view_header *w, struct dns_info *dns, int i)
{
    const node_t *node = list_begin(dns->record[i].rdata.txt);

    while (node) {
        struct dns_txt_rr *rr = (struct dns_txt_rr *) list_data(node);

        LV_ADD_TEXT_ELEMENT(lw, w, "TXT: %s", (rr->txt == NULL) ? "" : rr->txt);
        LV_ADD_TEXT_ELEMENT(lw, w, "TXT length: %d", rr->len);
        node = list_next(node);
    }
}

static void add_dns_soa(list_view *lw, list_view_header *w, struct dns_info *dns, int i)
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

static void add_dns_opt(list_view *lw, list_view_header *w, struct dns_info *dns, int i)
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

static void add_dns_record(list_view *lw, list_view_header *w, struct dns_info *dns, int i, uint16_t type)
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
        if (!dns->record[i].rdata.nsec.types)
            return;
        for (unsigned int j = 0; j < dns->record[i].rdata.nsec.num_types; j++) {
            LV_ADD_TEXT_ELEMENT(lw, w, "Type in bitmap: %s",
                             get_dns_type_extended(dns->record[i].rdata.nsec.types[j]));
        }
        break;
    default:
        break;
    }
}

static void add_dns_record_hdr(list_view *lw, list_view_header *header, struct dns_info *dns,
                        int idx, int max_record_name)
{
    char buffer[MAXLINE];
    list_view_header *w;
    char *type;

    buffer[0] = 0;
    /* the OPT resource record has special handling of the fixed parts of the record */
    if (dns->record[idx].type == DNS_TYPE_OPT) {
        if (!dns->record[idx].name[0]) { /* the name must be 0 (root domain) */
            if (max_record_name == 0) {
                snprintf(buffer, MAXLINE, "%-*s", DNS_RD_LEN + 4, DNS_ROOT_DOMAIN);
            } else {
                snprintf(buffer, MAXLINE, "%-*s", max_record_name + 4, DNS_ROOT_DOMAIN);
            }
        } else {
            snprintf(buffer, MAXLINE, "%-*s", max_record_name + 4, dns->record[idx].name);
        }
        /* class is the requestor's UDP payload size*/
        snprintcat(buffer, MAXLINE, "%-6d", GET_MDNS_RRCLASS(dns->record[idx].rrclass));
    } else if (dns->record[idx].name[0]) {
        snprintf(buffer, MAXLINE, "%-*s", max_record_name + 4, dns->record[idx].name);
        snprintcat(buffer, MAXLINE, "%-8s", get_dns_class(GET_MDNS_RRCLASS(dns->record[idx].rrclass)));
    }
    type = get_dns_type(dns->record[idx].type);
    snprintcat(buffer, MAXLINE, "%-8s", type);
    print_dns_record(dns, idx, buffer, MAXLINE, dns->record[idx].type);
    w = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER2], UI_SUBLAYER2, "%s", buffer);
    add_dns_record(lw, w, dns, idx, dns->record[idx].type);
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
    if (dns->question && dns->section_count[QDCOUNT]) {
        list_view_header *hdr;
        char *type;

        hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Questions");
        for (unsigned int i = 0; i < dns->section_count[QDCOUNT]; i++) {
            if ((type = get_dns_type_extended(dns->question[i].qtype)))
                LV_ADD_TEXT_ELEMENT(lw, hdr, "QNAME: %s, QTYPE: %s, QCLASS: %s",
                                    dns->question[i].qname,
                                    type,
                                    get_dns_class_extended(GET_MDNS_RRCLASS(dns->question[i].qclass)));
        }
    }
    if (records > 0 && dns->record) {
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

static void add_nbns_record(list_view *lw, list_view_header *w, struct nbns_info *nbns, int i, uint16_t type)
{
    char time[512];
    struct tm_t tm;
    char *def;

    if ((def = get_nbns_suffix(nbns->record[i].rrname)) != NULL)
        LV_ADD_TEXT_ELEMENT(lw, w, "Name: %s (%s)", nbns->record[i].rrname, def);
    else
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
        char addr[INET_ADDRSTRLEN];

        flags = nbns->record[i].rdata.nb.g << 2 | nbns->record[i].rdata.nb.ont;
        hdr = LV_ADD_SUB_HEADER(lw, w, selected[UI_FLAGS], UI_FLAGS, "NB flags (0x%x)", flags);
        add_flags(lw, hdr, flags, get_nbns_nb_flags(), get_nbns_nb_flags_size());
        for (int j = 0; j < nbns->record[i].rdata.nb.num_addr; j++) {
            inet_ntop(AF_INET, nbns->record[i].rdata.nb.address + j, addr, INET_ADDRSTRLEN);
            LV_ADD_TEXT_ELEMENT(lw, w, "Name owner address: %s", addr);
        }
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

static void add_nbns_record_hdr(list_view *lw, list_view_header *header, struct nbns_info *nbns, int i)
{
    char buffer[MAXLINE];
    list_view_header *hdr;

    if (nbns->record[i].rrname[0] == 0)
        return;
    snprintf(buffer, MAXLINE, "%s\t", nbns->record[i].rrname);
    snprintcat(buffer, MAXLINE, "IN\t");
    snprintcat(buffer, MAXLINE, "%s\t", get_nbns_type(nbns->record[i].rrtype));
    print_nbns_record(nbns, i, buffer, MAXLINE);
    hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "%s", buffer);
    add_nbns_record(lw, hdr, nbns, i, nbns->record[i].rrtype);
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
        if (nbds->msg.dgm) {
            LV_ADD_TEXT_ELEMENT(lw, header, "Datagram length: %u bytes", nbds->msg.dgm->dgm_length);
            LV_ADD_TEXT_ELEMENT(lw, header, "Packet offset: %u", nbds->msg.dgm->packet_offset);
            LV_ADD_TEXT_ELEMENT(lw, header, "Source name: %s", nbds->msg.dgm->src_name);
            LV_ADD_TEXT_ELEMENT(lw, header, "Destination name: %s", nbds->msg.dgm->dest_name);
        }
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
        list_view_header *q;
        list_view_header *sub;
        char *def;

        q = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Questions");
        sub = LV_ADD_SUB_HEADER(lw, q, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                "%s  Type: %s  Class: IN",
                                nbns->question.qname, get_nbns_type(nbns->question.qtype));
        if ((def = get_nbns_suffix(nbns->question.qname)) != NULL)
            LV_ADD_TEXT_ELEMENT(lw, sub, "Name: %s (%s)", nbns->question.qname, def);
        else
            LV_ADD_TEXT_ELEMENT(lw, sub, "Name: %s", nbns->question.qname);
        LV_ADD_TEXT_ELEMENT(lw, sub, "Type: %s", get_nbns_type_extended(nbns->question.qtype));
        LV_ADD_TEXT_ELEMENT(lw, sub, "Class: IN (Internet)");
    }
    if (records > 0 && nbns->record) {
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
    list_view_header *hdata;


    if (http->start_line && http->header) {
        LV_ADD_TEXT_ELEMENT(lw, header, "%s", http->start_line);
        n = rbtree_first(http->header);
        while (n) {
            LV_ADD_TEXT_ELEMENT(lw, header, "%s: %s", (char *) rbtree_get_key(n),
                                (char *) rbtree_get_data(n));
            n = rbtree_next(http->header, n);
        }
        if (http->len) {
            hdata = LV_ADD_HEADER(lw, "Data", selected[UI_SUBLAYER1], UI_SUBLAYER1);
            add_hexdump(lw, hdata, hexmode, http->data, http->len);
        }
    } else if (http->len) {
        hdata = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Data");
        add_hexdump(lw, hdata, hexmode, http->data, http->len);
    }

}

static void add_snmp_variables(list_view *lw, list_view_header *header, list_t *vars)
{
    const node_t *n = list_begin(vars);

    while (n) {
        struct snmp_varbind *var = list_data(n);
        list_view_header *hdr;

        switch (var->type) {
        case SNMP_INTEGER_TAG:
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER2], UI_SUBLAYER2, "%s: %ld",
                                 var->object_name, var->object_syntax.ival);
            LV_ADD_TEXT_ELEMENT(lw, hdr, "Object name: %s", var->object_name);
            LV_ADD_TEXT_ELEMENT(lw, hdr, "Value: %ld", var->object_syntax.ival);
            break;
        case SNMP_NULL_TAG:
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER2], UI_SUBLAYER2, "%s: null",
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
                hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER2], UI_SUBLAYER2, "%s: %s",
                                     var->object_name, var->object_syntax.pval);
                LV_ADD_TEXT_ELEMENT(lw, hdr, "Object name: %s", var->object_name);
                LV_ADD_TEXT_ELEMENT(lw, hdr, "Value: %s (%s)", var->object_syntax.pval, buf);
            } else {
                hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER2], UI_SUBLAYER2, "%s: %s",
                                     var->object_name, buf);
                LV_ADD_TEXT_ELEMENT(lw, hdr, "Object name: %s", var->object_name);
                LV_ADD_TEXT_ELEMENT(lw, hdr, "Value: %s", buf);
            }
            break;
        }
        case SNMP_OBJECT_ID_TAG:
            hdr = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER2], UI_SUBLAYER2, "%s: %s",
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

static void add_snmp_pdu(list_view *lw, list_view_header *header, struct snmp_pdu *pdu)
{
    char *error;

    LV_ADD_TEXT_ELEMENT(lw, header, "Request ID: %d", pdu->request_id);
    if ((error = get_snmp_error_status(pdu)))
        LV_ADD_TEXT_ELEMENT(lw, header, "Error status: %s (%d)", error, pdu->error_status);
    else
        LV_ADD_TEXT_ELEMENT(lw, header, "Error status: %d", pdu->error_status);
    LV_ADD_TEXT_ELEMENT(lw, header, "Error index: %d", pdu->error_index);
    if (pdu->varbind_list)
        add_snmp_variables(lw, header, pdu->varbind_list);
}

static void add_snmp_trap(list_view *lw, list_view_header *header, struct snmp_trap *pdu)
{
    char *trap;

    LV_ADD_TEXT_ELEMENT(lw, header, "Enterprise: %s", pdu->enterprise);
    LV_ADD_TEXT_ELEMENT(lw, header, "Agent address: %s", pdu->agent_addr);
    if ((trap = get_snmp_trap_type(pdu)))
        LV_ADD_TEXT_ELEMENT(lw, header, "Trap type: %s (%d)", trap, pdu->trap_type);
    else
        LV_ADD_TEXT_ELEMENT(lw, header, "Trap type: %d", pdu->trap_type);
    LV_ADD_TEXT_ELEMENT(lw, header, "Specific code: %d", pdu->specific_code);
    if (pdu->varbind_list)
        add_snmp_variables(lw, header, pdu->varbind_list);
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
    if (!snmp->pdu && !snmp->trap)
        return;
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
        char *buf = xmalloc(smtp->len + 1);
        unsigned int c = 0;

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
        if (c < smtp->len) {
            buf[smtp->len] = '\0';
            LV_ADD_TEXT_ELEMENT(lw, header, "%s", buf + c);
        }
        free(buf);
    } else {
        if (smtp->response && smtp->rsps) {
            const node_t *n;

            DLIST_FOREACH(smtp->rsps, n) {
                const node_t *line;
                struct smtp_rsp *rsp;
                char *code;

                rsp = list_data(n);
                code = get_smtp_code(rsp->code);
                if (code)
                    LV_ADD_TEXT_ELEMENT(lw, header, "Reply code %d: %s",
                                        rsp->code, code);
                else
                    LV_ADD_TEXT_ELEMENT(lw, header, "Reply code %d", rsp->code);
                DLIST_FOREACH(rsp->lines, line)
                    LV_ADD_TEXT_ELEMENT(lw, header, "Reply parameters: %s",
                                        (char *) list_data(line));
            }
        } else if (smtp->cmds) {
            const node_t *n;
            struct smtp_cmd *cmd;

            DLIST_FOREACH(smtp->cmds, n) {
                cmd = list_data(n);
                LV_ADD_TEXT_ELEMENT(lw, header, "Command: %s", cmd->command);
                LV_ADD_TEXT_ELEMENT(lw, header, "Parameters: %s", cmd->params);
            }
        }
    }
}


static void add_dhcp_options(list_view *lw, list_view_header *header, struct dhcp_info *dhcp)
{
    const node_t *node;
    char buf[256] = { 0 };
    struct tm_t t;
    uint32_t addr;

    DLIST_FOREACH(dhcp->options, node) {
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
                /* LV_ADD_TEXT_ELEMENT(lw, opthdr, "Hardware type: %s (%d)", */
                /*                     get_arp_hardware_type(opt->bytes[0]), opt->bytes[0]); */
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

            fhdr = LV_ADD_SUB_HEADER(lw, opthdr, selected[UI_FLAGS], UI_FLAGS, "Flags: 0x%x", opt->fqdn.flags);
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
    /* if ((str = get_arp_hardware_type(dhcp->htype)) != NULL) */
    /*     LV_ADD_TEXT_ELEMENT(lw, header, "Hardware address type: %s (%d)", str, dhcp->htype); */
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

static void add_tls_extensions(list_view *lw, list_view_header *header,
                               struct tls_extension *ext)
{
    list_view_header *sub;

    while (ext) {
        switch(ext->type) {
        case SUPPORTED_GROUPS:
        {
            char *group;

            sub = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                    "Extension: Supported groups");
            LV_ADD_TEXT_ELEMENT(lw, sub, "Length: %u", ext->supported_groups.length);
            for (int i = 0; i < ext->supported_groups.length / 2; i++) {
                if ((group = get_supported_group(ntohs(ext->supported_groups.named_group_list[i])))) {
                    LV_ADD_TEXT_ELEMENT(lw, sub, "%s", group);
                }
            }
            break;
        }
        case EC_POINT_FORMATS:
            sub = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                    "Extension: EC Point Formats");
            LV_ADD_TEXT_ELEMENT(lw, sub, "Length: %u", ext->ec_point.length);
            for (int i = 0; i < ext->ec_point.length; i++) {
                char *format;

                if ((format = get_ec_point_format(ext->ec_point.format_list[i])))
                    LV_ADD_TEXT_ELEMENT(lw, sub, "%s", format);
                else
                    LV_ADD_TEXT_ELEMENT(lw, sub, "%d", ext->ec_point.format_list[i]);
            }
            break;
        case SIGNATURE_ALGORITHMS:
        {
            char *alg;

            sub = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                    "Extension: Signature algorithms");
            LV_ADD_TEXT_ELEMENT(lw, sub, "Length: %u", ext->signature_algorithms.length);
            for (int i = 0; i < ext->signature_algorithms.length / 2; i++) {
                if ((alg = get_signature_scheme(ntohs(ext->signature_algorithms.types[i])))) {
                    LV_ADD_TEXT_ELEMENT(lw, sub, "%s", alg);
                }
            }
            break;
        }
        case SUPPORTED_VERSIONS:
            sub = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                    "Extension: Supported version");
            LV_ADD_TEXT_ELEMENT(lw, sub, "Length: %u", ext->supported_versions.length);
            for (int i = 0; i < ext->supported_versions.length / 2; i++)
                LV_ADD_TEXT_ELEMENT(lw, sub, "%s",
                                    get_tls_version(ntohs(ext->supported_versions.versions[i])));
            break;
        case SESSION_TICKET:
        {
            list_view_header *w;

            sub = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                    "Extension: Session ticket");
            LV_ADD_TEXT_ELEMENT(lw, sub, "Length: %u", ext->length);
            if (ext->length > 0) {
                w = LV_ADD_SUB_HEADER(lw, sub, selected[UI_SUBLAYER2], UI_SUBLAYER2, "Data");
                add_hexdump(lw, w, hexmode, ext->data, ext->length);
            }
            break;
        }
        case COOKIE:
            sub = LV_ADD_SUB_HEADER(lw, header, selected[UI_SUBLAYER1], UI_SUBLAYER1,
                                    "Extension: Cookie");
            LV_ADD_TEXT_ELEMENT(lw, sub, "Length: %u", ext->length);
            if (ext->length > 0) {
                char *buf = xmalloc(ext->length * 2);

                for (int i = 0; i < ext->length; i++)
                    snprintf(buf + 2 * i, 3, "%02x", ext->data[i]);
                LV_ADD_TEXT_ELEMENT(lw, sub, "%s", buf);
                free(buf);
            }
            break;
        default:
            break;
        }
        ext = ext->next;
    }
}

static void add_tls_client_hello(list_view *lw, list_view_header *hdr, struct tls_handshake *hs)
{
    struct tls_handshake_client_hello *hello;
    list_view_header *sub;
    char buf[65];

    hello = hs->client_hello;
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Protocol Version: %s", get_tls_version(hello->legacy_version));
    for (int i = 0; i < 32; i++)
        snprintf(buf + 2 * i, 3, "%02x", hello->random_bytes[i]);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Random bytes: %s", buf);
    if (!hello->session_id)
        return;
    for (int i = 0; i < hello->session_length; i++)
        snprintf(buf + 2 * i, 3, "%02x", hello->session_id[i]);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Session id length: %d", hello->session_length);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Session id: %s", buf);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Cipher suite length: %d", hello->cipher_length);
    sub = LV_ADD_SUB_HEADER(lw, hdr, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Ciper Suites");
    if (!hello->cipher_suites)
        return;
    for (int i = 0; i < hello->cipher_length / 2; i++) {
        LV_ADD_TEXT_ELEMENT(lw, sub, "%s (0x%04x)",
                            get_tls_cipher_suite(ntohs(hello->cipher_suites[i])),
                            ntohs(hello->cipher_suites[i]));
    }
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Compression length: %d", hello->compression_length);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Extension length: %u", hs->ext_length);
    add_tls_extensions(lw, hdr, hs->ext);
}

static void add_tls_server_hello(list_view *lw, list_view_header *hdr, struct tls_handshake *hs)
{
    struct tls_handshake_server_hello *hello;
    char buf[65];

    hello = hs->server_hello;
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Protocol Version: %s",
                        get_tls_version(hello->legacy_version));
    for (int i = 0; i < 32; i++)
        snprintf(buf + 2 * i, 3, "%02x", hello->random_bytes[i]);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Random bytes: %s", buf);
    if (!hello->session_id)
        return;
    for (int i = 0; i < hello->session_length; i++)
        snprintf(buf + 2 * i, 3, "%02x", hello->session_id[i]);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Session id length: %d", hello->session_length);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Session id: %s", buf);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Cipher suite: %s (0x%x)",
                        get_tls_cipher_suite(hello->cipher_suite), hello->cipher_suite);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Compression: %d", hello->compression_method);
    LV_ADD_TEXT_ELEMENT(lw, hdr, "Extension length: %u", hs->ext_length);
    add_tls_extensions(lw, hdr, hs->ext);
}

static void add_tls_handshake(list_view *lw, list_view_header *header,
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
            if (handshake->client_hello)
                add_tls_client_hello(lw, hdr, handshake);
            break;
        case TLS_SERVER_HELLO:
            if (handshake->server_hello)
                add_tls_server_hello(lw, hdr, handshake);
            break;
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
    list_view_header *sub;

    while (tls) {
        if (tls->type == TLS_HANDSHAKE && tls->handshake) {
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
            if (tls->handshake)
                add_tls_handshake(lw, record, tls->handshake);
            break;
        case TLS_APPLICATION_DATA:
            sub = LV_ADD_SUB_HEADER(lw, record, selected[UI_SUBLAYER1], UI_SUBLAYER1, "Data");
            add_hexdump(lw, sub, hexmode, tls->data, tls->length);
            break;
        default:
            break;
        }
        tls = tls->next;
    }
}

void add_vrrp_information(void *w, void *sw, void *data)
{
    list_view *lv = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    struct vrrp_info *vrrp = pdata->data;
    char *type, *auth;

    LV_ADD_TEXT_ELEMENT(lv, header, "Version: %u", vrrp->version);
    if ((type = get_vrrp_type(vrrp->type)))
        LV_ADD_TEXT_ELEMENT(lv, header, "Type: %s (%u)", type, vrrp->type);
    else
        LV_ADD_TEXT_ELEMENT(lv, header, "Type: (%u)", vrrp->type);
    LV_ADD_TEXT_ELEMENT(lv, header, "Virtual router ID: %u", vrrp->vrid);
    LV_ADD_TEXT_ELEMENT(lv, header, "Priority: %s (%u)",
                        get_vrrp_priority(vrrp->priority), vrrp->priority);
    LV_ADD_TEXT_ELEMENT(lv, header, "IP address count: %u", vrrp->count_ip);
    if (vrrp->version < 3) {
        if ((auth = get_vrrp_auth(vrrp->type)))
            LV_ADD_TEXT_ELEMENT(lv, header, "Authentication type: %s (%u) [Reserved version 2]",
                                auth, vrrp->v.auth_type);
        else
            LV_ADD_TEXT_ELEMENT(lv, header, "Authentication type: %u", vrrp->v.auth_type);
        LV_ADD_TEXT_ELEMENT(lv, header, "Advertisement interval: %u s.", vrrp->v.advr_int);
    } else {
        LV_ADD_TEXT_ELEMENT(lv, header, "Maximum advertisement interval: %u cs.",
                            vrrp->v3.max_advr_int);
    }
    LV_ADD_TEXT_ELEMENT(lv, header, "Checksum: 0x%x", vrrp->checksum);
    if (get_protocol_key(pdata->prev->id) == ETHERTYPE_IP && vrrp->ip4_addrs) {
        char ip4_addr[INET_ADDRSTRLEN];

        for (int i = 0; i < vrrp->count_ip; i++) {
            inet_ntop(AF_INET, vrrp->ip4_addrs + i, ip4_addr, INET_ADDRSTRLEN);
            LV_ADD_TEXT_ELEMENT(lv, header, "IPv4 Address: %s", ip4_addr);
        }
    } else if (vrrp->ip6_addrs) {
        char ip6_addr[INET6_ADDRSTRLEN];

        for (int i = 0; i < vrrp->count_ip; i++) {
            inet_ntop(AF_INET6, vrrp->ip6_addrs + i * 16, ip6_addr, INET6_ADDRSTRLEN);
            LV_ADD_TEXT_ELEMENT(lv, header, "IPv6 Address: %s", ip6_addr);
        }
    }
    if (vrrp->version < 3 && vrrp->v.auth_type == VRRP_V1_AUTH_STP && vrrp->v.auth_str[0] != '\0')
        LV_ADD_TEXT_ELEMENT(lv, header, "Authentication string: %s", vrrp->v.auth_str);
}

void add_loop_information(void *w, void *sw, void *data)
{
    list_view *lv = w;
    list_view_header *header = sw;
    struct packet_data *pdata = data;
    char buf[MAXLINE] = { 0 };

    loop2string(buf, MAXLINE, pdata->data);
    LV_ADD_TEXT_ELEMENT(lv, header, "%s", buf);
}
