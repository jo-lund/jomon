#ifndef PCAP_LEXER_H
#define PCAP_LEXER_H

#include <stdint.h>
#include <stdbool.h>

enum pcap_token {
    PCAP_ERR_OVERFLOW = -1,
    PCAP_EOF,
    PCAP_HOST,
    PCAP_NET,
    PCAP_PORT,
    PCAP_PORTRANGE,
    PCAP_ETHER,
    PCAP_TR,
    PCAP_WLAN,
    PCAP_IP,
    PCAP_IP6,
    PCAP_ARP,
    PCAP_RARP,
    PCAP_DECNET,
    PCAP_ATALK,
    PCAP_AARP,
    PCAP_SCA,
    PCAP_LAT,
    PCAP_MOPDL,
    PCAP_MOPRC,
    PCAP_ISO,
    PCAP_STP,
    PCAP_IPX,
    PCAP_NETBEUI,
    PCAP_LLC,
    PCAP_TCP,
    PCAP_UDP,
    PCAP_ICMP,
    PCAP_ICMP6,
    PCAP_IGMP,
    PCAP_IGMPR,
    PCAP_PIM,
    PCAP_AH,
    PCAP_ESP,
    PCAP_VRRP,
    PCAP_GATEWAY,
    PCAP_BROADCAST,
    PCAP_MULTICAST,
    PCAP_LESS,
    PCAP_GREATER,
    PCAP_PROTOCHAIN,
    PCAP_SRC,
    PCAP_DST,
    PCAP_LAND,
    PCAP_LOR,
    PCAP_NOT,
    PCAP_EQ,
    PCAP_LE,
    PCAP_GT,
    PCAP_GEQ,
    PCAP_LEQ,
    PCAP_NEQ,
    PCAP_SHL,
    PCAP_SHR,
    PCAP_MUL,
    PCAP_DIV,
    PCAP_MOD,
    PCAP_ADD,
    PCAP_SUB,
    PCAP_AND,
    PCAP_XOR,
    PCAP_OR,
    PCAP_ID,
    PCAP_IPADDR,
    PCAP_HWADDR,
    PCAP_INT,
    PCAP_LPAR,
    PCAP_RPAR,
    PCAP_LBRACKET,
    PCAP_RBRACKET,
    PCAP_COL
};

struct bpf_parser;

int pcap_lex(struct bpf_parser *parser);

#endif
