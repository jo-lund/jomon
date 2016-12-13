#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ctype.h>
#include "../misc.h"
#include "../error.h"
#include "packet.h"
#include "packet_dns.h"
#include "packet_nbns.h"
#include "packet_http.h"
#include "packet_stp.h"
#include "packet_arp.h"
#include "packet_ip.h"
#include "packet_ssdp.h"

#define MULTICAST_ADDR_MASK 0xe

static uint32_t packet_count = 0;

static void free_protocol_data(struct application_info *info);

size_t read_packet(int sockfd, unsigned char *buffer, size_t len, struct packet **p)
{
    int n;

    *p = calloc(1, sizeof(struct packet));
    if ((n = read(sockfd, buffer, len)) == -1) {
        free_packet(*p);
        err_sys("read error");
    }
    if (!handle_ethernet(buffer, n, &(*p)->eth)) {
        free_packet(*p);
        return 0;
    }
    (*p)->num = ++packet_count;
    return n;
}

bool decode_packet(unsigned char *buffer, size_t len, struct packet **p)
{
    *p = calloc(1, sizeof(struct packet));
    if (!handle_ethernet(buffer, len, &(*p)->eth)) {
        free_packet(p);
        return false;
    }
    (*p)->num = ++packet_count;
    return true;
}

void free_packet(void *data)
{
    struct packet *p = (struct packet *) data;

    if (p->eth.ethertype < ETH_P_802_3_MIN) {
        if (p->eth.llc->dsap == 0xaa && p->eth.llc->ssap == 0xaa) {
            if (p->eth.llc->snap->payload) {
                free(p->eth.llc->snap->payload);
            }
            free(p->eth.llc->snap);
        } else if (p->eth.llc->dsap == 0x42 && p->eth.llc->ssap == 0x42) {
            free(p->eth.llc->bpdu);
        } else if (p->eth.llc->payload) {
            free(p->eth.llc->payload);
        }
        free(p->eth.llc);
        return;
    }
    switch (p->eth.ethertype) {
    case ETH_P_IP:
        switch (p->eth.ip->protocol) {
        case IPPROTO_UDP:
            free_protocol_data(&p->eth.ip->udp.data);
            break;
        case IPPROTO_TCP:
            free_protocol_data(&p->eth.ip->tcp.data);
            if (p->eth.ip->tcp.options) {
                free(p->eth.ip->tcp.options);
            }
            break;
        case IPPROTO_ICMP:
        case IPPROTO_IGMP:
            break;
        default:
            if (p->eth.ip->payload) {
                free(p->eth.ip->payload);
            }
            break;
        }
        free(p->eth.ip);
        break;
    case ETH_P_IPV6:
        switch (p->eth.ipv6->next_header) {
        case IPPROTO_UDP:
            free_protocol_data(&p->eth.ipv6->udp.data);
            break;
        case IPPROTO_TCP:
            free_protocol_data(&p->eth.ipv6->tcp.data);
            if (p->eth.ipv6->tcp.options) {
                free(p->eth.ipv6->tcp.options);
            }
            break;
        case IPPROTO_ICMP:
        case IPPROTO_IGMP:
            break;
        default:
            if (p->eth.ipv6->payload) {
                free(p->eth.ipv6->payload);
            }
            break;
        }
        free(p->eth.ipv6);
        break;
    case ETH_P_ARP:
        free(p->eth.arp);
        break;
    default:
        if (p->eth.payload_len) {
            free(p->eth.payload);
        }
        break;
    }
    free(p);
}

void free_protocol_data(struct application_info *info)
{
    switch (info->utype) {
    case DNS:
        if (info->dns) {
            if (info->dns->record) {
                switch (info->dns->record->type) {
                case DNS_TYPE_HINFO:
                    free(info->dns->record->rdata.hinfo.cpu);
                    free(info->dns->record->rdata.hinfo.os);
                    break;
                case DNS_TYPE_TXT:
                    list_free(info->dns->record->rdata.txt);
                    break;
                default:
                    break;
                }
                free(info->dns->record);
            }
            free(info->dns);
        }
        break;
    case NBNS:
        if (info->nbns) {
            if (info->nbns->record) {
                free(info->nbns->record);
            }
            free(info->nbns);
        }
        break;
    case SSDP:
        if (info->ssdp) {
            list_free(info->ssdp);
        }
        break;
    case HTTP:
        if (info->http) {
            if (info->http->start_line) {
                free(info->http->start_line);
            }
            if (info->http->header) {
                list_free(info->http->header);
            }
            if (info->http->data) {
                free(info->http->data);
            }
            free(info->http);
        }
        break;
    default:
        if (info->payload) {
            free(info->payload);
        }
        break;
    }
}

/*
 * Checks which well-known or registered port the packet originated from or is
 * addressed to. On error the error argument will be set to true, e.g. if
 * checksum correction is enabled and this calculation fails.
 *
 * Returns false if it's an ephemeral port, the port is not yet supported or in
 * case of errors in decoding the packet.
 */
bool check_port(unsigned char *buffer, int n, struct application_info *info,
                uint16_t port, bool *error)
{
    switch (port) {
    case DNS:
    case MDNS:
        return handle_dns(buffer, n, info);
    case NBNS:
        return handle_nbns(buffer, n, info);
    case SSDP:
        return handle_ssdp(buffer, n, info);
    /* case HTTP: */
    /*     *error = handle_http(buffer, info, packet_len); */
    /*     return true; */
    default:
        return false;
    }
}
