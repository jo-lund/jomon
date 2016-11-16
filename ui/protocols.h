#ifndef UI_PROTOCOLS_H
#define UI_PROTOCOLS_H

#include <decoder.h>
#include "list_view.h"

#define ADDR_WIDTH 36
#define PROT_WIDTH 10
#define NUM_WIDTH 10

/* write packet to buffer */
void print_buffer(char *buf, int size, struct packet *p);

int print_tcp_options(WINDOW *win, struct tcp *tcp, int y);
int print_dns_verbose(WINDOW *win, struct dns_info *dns, int y, int maxx);
int print_nbns_verbose(WINDOW *win, struct nbns_info *nbns, int y, int maxx);

void print_ethernet_information(list_view *lw, struct packet *p);
void print_arp_information(list_view *lw, struct packet *p);
void print_llc_information(list_view *lw, struct packet *p);
void print_snap_information(list_view *lw, struct packet *p);
void print_stp_information(list_view *lw, struct packet *p);
void print_ip_information(list_view *lw, struct ip_info *ip);
void print_udp_information(list_view *lw, struct ip_info *ip);
void print_tcp_information(list_view *lw, struct ip_info *ip);
void print_icmp_information(list_view *lw, struct ip_info *ip);
void print_igmp_information(list_view *lw, struct ip_info *info);
void print_ssdp_information(list_view *lw, list_t *ssdp);
void print_http_information(list_view *lw, struct http_info *http);
void print_payload(list_view *lw, unsigned char *payload, uint16_t len);

#endif