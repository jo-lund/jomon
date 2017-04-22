#ifndef UI_PROTOCOLS_H
#define UI_PROTOCOLS_H

#include <decoder.h>
#include "list_view.h"

#define ADDR_WIDTH 40
#define PROT_WIDTH 10
#define NUM_WIDTH 10
#define TIME_WIDTH 20

/* write packet to buffer */
void print_buffer(char *buf, int size, struct packet *p);

void add_ethernet_information(list_view *lw, list_view_item *header, struct packet *p);
void add_arp_information(list_view *lw, list_view_item *header, struct packet *p);
void add_llc_information(list_view *lw, list_view_item *header, struct packet *p);
void add_snap_information(list_view *lw, list_view_item *header, struct packet *p);
void add_stp_information(list_view *lw, list_view_item *header, struct packet *p);
void add_ipv4_information(list_view *lw, list_view_item *header, struct ip_info *ip);
void add_ipv6_information(list_view *lw, list_view_item *header, struct ipv6_info *ip);
void add_udp_information(list_view *lw, list_view_item *header, struct udp_info *udp);
void add_tcp_information(list_view *lw, list_view_item *header, struct tcp *tcp,
                         bool options_selected);
void add_icmp_information(list_view *lw, list_view_item *header, struct icmp_info *icmp);
void add_igmp_information(list_view *lw, list_view_item *header, struct igmp_info *igmp);
void add_pim_information(list_view *lw, list_view_item *header, struct pim_info *pim,
                         bool msg_selected);
void add_ssdp_information(list_view *lw, list_view_item *header, list_t *ssdp);
void add_http_information(list_view *lw, list_view_item *header, struct http_info *http);
void add_dns_information(list_view *lw, list_view_item *header, struct dns_info *dns,
                         bool records_selected);
void add_nbns_information(list_view *lw, list_view_item *header, struct nbns_info *nbns);
void add_payload(list_view *lw, list_view_item *header, unsigned char *payload, uint16_t len);

#endif
