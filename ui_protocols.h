#include "packet.h"

#define ADDR_WIDTH 36
#define PROT_WIDTH 10

/* write packet to buffer */
void print_buffer(char *buf, int size, struct packet *p);

void print_ethernet_verbose(WINDOW *win, struct packet *p, int lineno, int y);
void print_arp_verbose(WINDOW *win, struct packet *p, int lineno, int y);
void print_ip_verbose(WINDOW *win, struct ip_info *ip, int lineno, int y);
void print_udp_verbose(WINDOW *win, struct ip_info *ip, int lineno, int y);
void print_tcp_verbose(WINDOW *win, struct ip_info *ip, int lineno, int y);
void print_dns_verbose(WINDOW *win, struct dns_info *dns, int lineno, int y, int maxx);
void print_dns_soa(WINDOW *win, struct dns_info *info, int i, int lineno, int y, int x);
void print_nbns_verbose(WINDOW *win, struct nbns_info *nbns, int lineno, int y, int maxx);
void print_icmp_verbose(WINDOW *win, struct ip_info *ip, int lineno, int y);
void print_igmp_verbose(WINDOW *win, struct ip_info *info, int lineno, int y);
void print_ssdp_verbose(WINDOW *win, list_t *ssdp, int lineno, int y);
void print_http_verbose(WINDOW *win, struct http_info *http);
