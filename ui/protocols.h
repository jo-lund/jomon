#ifndef UI_PROTOCOLS_H
#define UI_PROTOCOLS_H

#include <decoder.h>
#include "list_view.h"

#define ADDR_WIDTH 36
#define PROT_WIDTH 10
#define NUM_WIDTH 10

/* write packet to buffer */
void print_buffer(char *buf, int size, struct packet *p);

void print_ethernet_information(list_view *lw, list_view_item *header, struct packet *p);
void print_arp_information(list_view *lw, list_view_item *header, struct packet *p);
void print_llc_information(list_view *lw, list_view_item *header, struct packet *p);
void print_snap_information(list_view *lw, list_view_item *header, struct packet *p);
void print_stp_information(list_view *lw, list_view_item *header, struct packet *p);
void print_ip_information(list_view *lw, list_view_item *header, struct ip_info *ip);
void print_udp_information(list_view *lw, list_view_item *header, struct ip_info *ip);
void print_tcp_information(list_view *lw, list_view_item *header, struct ip_info *ip, bool options_selected);
void print_icmp_information(list_view *lw, list_view_item *header, struct ip_info *ip);
void print_igmp_information(list_view *lw, list_view_item *header, struct ip_info *info);
void print_ssdp_information(list_view *lw, list_view_item *header, list_t *ssdp);
void print_http_information(list_view *lw, list_view_item *header, struct http_info *http);
void print_dns_information(list_view *lw, list_view_item *header, struct dns_info *dns, int maxx);
void print_nbns_information(list_view *lw, list_view_item *header, struct nbns_info *nbns, int maxx);
void print_payload(list_view *lw, list_view_item *header, unsigned char *payload, uint16_t len);

#endif
