#ifndef UI_PROTOCOLS_H
#define UI_PROTOCOLS_H

#include <decoder.h>
#include "list_view.h"

#define ADDR_WIDTH 36
#define PROT_WIDTH 10
#define NUM_WIDTH 10

/* write packet to buffer */
void print_buffer(char *buf, int size, struct packet *p);

void add_ethernet_information(list_view *lw, list_view_item *header, struct packet *p);
void add_arp_information(list_view *lw, list_view_item *header, struct packet *p);
void add_llc_information(list_view *lw, list_view_item *header, struct packet *p);
void add_snap_information(list_view *lw, list_view_item *header, struct packet *p);
void add_stp_information(list_view *lw, list_view_item *header, struct packet *p);
void add_ip_information(list_view *lw, list_view_item *header, struct ip_info *ip);
void add_udp_information(list_view *lw, list_view_item *header, struct ip_info *ip);
void add_tcp_information(list_view *lw, list_view_item *header, struct ip_info *ip, bool options_selected);
void add_icmp_information(list_view *lw, list_view_item *header, struct ip_info *ip);
void add_igmp_information(list_view *lw, list_view_item *header, struct ip_info *info);
void add_ssdp_information(list_view *lw, list_view_item *header, list_t *ssdp);
void add_http_information(list_view *lw, list_view_item *header, struct http_info *http);
void add_dns_information(list_view *lw, list_view_item *header, struct dns_info *dns, 
                         bool records_selected, int maxx);
void add_nbns_information(list_view *lw, list_view_item *header, struct nbns_info *nbns, int maxx);
void add_payload(list_view *lw, list_view_item *header, unsigned char *payload, uint16_t len);

#endif
