#ifndef PACKET_IP6_H
#define PACKET_IP6_H

#define IPV6_FIXED_HEADER_LEN 40

struct ipv6_info {
    unsigned int version : 4;
    uint8_t tc;
    unsigned int flow_label : 20;
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src[16]; /* stored in network byte order */
    uint8_t dst[16]; /* stored in network byte order */
};

#define get_ipv6(p) ((struct ipv6_info *)(p)->root->next->data)
#define ipv6_src(p) get_ipv6(p)->src
#define ipv6_dst(p) get_ipv6(p)->dst
#define ipv6_protocol(p) get_ipv6(p)->next_header

/*
 * Parse 'count' number of ip6 addresses from buffer and store them in 'addrs'.
 * Return the new length of buffer.
 */
int parse_ipv6_addr(uint8_t *addrs, int count, unsigned char **buf, int n);

void register_ipv6(void);

#endif
