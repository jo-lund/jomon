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
void add_llc_information(void *w, void *sw, void *data);
void add_arp_information(void *w, void *sw, void *data);
void add_snap_information(void *w, void *sw, void *data);
void add_stp_information(void *w, void *sw, void *data);
void add_ipv4_information(void *w, void *sw, void *data);
void add_ipv6_information(void *w, void *sw, void *data);
void add_udp_information(void *w, void *sw, void *data);
void add_tcp_information(void *w, void *sw, void *data);
void add_igmp_information(void *w, void *sw, void *data);
void add_icmp_information(void *w, void *sw, void *data);
void add_pim_information(void *w, void *sw, void *data);
void add_dns_information(void *w, void *sw, struct application_info *adu);
void add_nbns_information(void *w, void *sw, struct application_info *adu);
void add_nbds_information(void *w, void *sw, struct application_info *adu);
void add_http_information(void *w, void *sw, struct application_info *adu);
void add_imap_information(void *w, void *sw, struct application_info *adu);
void add_snmp_information(void *w, void *sw, struct application_info *adu);
void add_ssdp_information(void *w, void *sw, struct application_info *adu);
void add_tls_information(void *w, void *sw, struct application_info *adu);

void print_llc(char *buf, int n, void *data);
void print_arp(char *buf, int n, void *data);
void print_ipv4(char *buf, int n, void *data);
void print_ipv6(char *buf, int n, void *data);
void print_udp(char *buf, int n, void *data);
void print_tcp(char *buf, int n, void *data);
void print_igmp(char *buf, int n, void *data);
void print_icmp(char *buf, int n, void *data);
void print_pim(char *buf, int n, void *data);
void print_dns(char *buf, int n, struct application_info *adu);
void print_nbns(char *buf, int n, struct application_info *adu);
void print_http(char *buf, int n, struct application_info *adu);
void print_imap(char *buf, int n, struct application_info *adu);
void print_snmp(char *buf, int n, struct application_info *adu);
void print_ssdp(char *buf, int n, struct application_info *adu);
void print_tls(char *buf, int n, struct application_info *adu);
void print_nbds(char *buf, int n, struct application_info *adu);

#endif
