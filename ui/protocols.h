#ifndef UI_PROTOCOLS_H
#define UI_PROTOCOLS_H

#include <decoder.h>
#include "list_view.h"

#define ADDR_WIDTH 40
#define PROT_WIDTH 10
#define NUM_WIDTH 10
#define TIME_WIDTH 20

/* write packet to buffer */
void write_to_buf(char *buf, int size, struct packet *p);

/* add protocol headers to the list view widget */
void add_ethernet_information(list_view *lw, list_view_header *header, struct packet *p);
void add_arp_information(list_view *lw, list_view_header *header, struct packet *p);
void add_llc_information(list_view *lw, list_view_header *header, struct packet *p);
void add_snap_information(list_view *lw, list_view_header *header, struct packet *p);
void add_stp_information(list_view *lw, list_view_header *header, struct packet *p);
void add_ipv4_information(list_view *lw, list_view_header *header, struct ipv4_info *ip);
void add_ipv6_information(list_view *lw, list_view_header *header, struct ipv6_info *ip);
void add_udp_information(list_view *lw, list_view_header *header, struct udp_info *udp);
void add_tcp_information(list_view *lw, list_view_header *header, struct tcp *tcp);
void add_icmp_information(list_view *lw, list_view_header *header, struct icmp_info *icmp);
void add_igmp_information(list_view *lw, list_view_header *header, struct igmp_info *igmp);
void add_pim_information(list_view *lw, list_view_header *header, struct pim_info *pim);

void add_dns_information(void *w, void *sw, struct application_info *adu);
void add_nbns_information(void *w, void *sw, struct application_info *adu);
void add_nbds_information(void *w, void *sw, struct application_info *adu);
void add_http_information(void *w, void *sw, struct application_info *adu);
void add_imap_information(void *w, void *sw, struct application_info *adu);
void add_snmp_information(void *w, void *sw, struct application_info *adu);
void add_ssdp_information(void *w, void *sw, struct application_info *adu);
void add_tls_information(void *w, void *sw, struct application_info *adu);
void print_dns(char *buf, int n, struct application_info *adu);
void print_nbns(char *buf, int n, struct application_info *adu);
void print_http(char *buf, int n, struct application_info *adu);
void print_imap(char *buf, int n, struct application_info *adu);
void print_snmp(char *buf, int n, struct application_info *adu);
void print_ssdp(char *buf, int n, struct application_info *adu);
void print_tls(char *buf, int n, struct application_info *adu);
void print_nbds(char *buf, int n, struct application_info *adu);

#endif
