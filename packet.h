#ifndef PACKET_H
#define PACKET_H

#include <netinet/in.h>

/* hardware address length (format aa:bb:cc:dd:ee:ff) */
#define HW_ADDRSTRLEN 18

#define UDP_HDRLEN 8
#define DNS_HDRLEN 12
#define DNS_NAMELEN 255

/* DNS opcodes */
#define QUERY 0  /* standard query */
#define IQUERY 1 /* inverse query */
#define STATUS 2 /* server status request */

/* DNS response codes */
#define NO_ERROR 0         /* no error condition */
#define FORMAT_ERROR 1     /* name server was unable to interpret the query */
#define SERVER_FAILURE 2   /* name server was unable to process the query */
#define NAME_ERROR 3       /* the domain name referenced in the query does not exist */
#define NOT_IMPLEMENTED 4  /* name server does not support the requested kind of query */
#define REFUSED 5          /* name server refuses to perform the specified operation */

/* DNS types */
#define DNS_TYPE_A 1       /* a host address */
#define DNS_TYPE_NS 2      /* an authoritative name server */
#define DNS_TYPE_MD 3      /* a mail destination (Obsolete - use MX) */
#define DNS_TYPE_MF 4      /* a mail forwarder (Obsolete - use MX) */
#define DNS_TYPE_CNAME 5   /* the canonical name for an alias */
#define DNS_TYPE_SOA 6     /* marks the start of a zone of authority */
#define DNS_TYPE_MB 7      /* a mailbox domain name (EXPERIMENTAL) */
#define DNS_TYPE_MG 8      /* a mail group member (EXPERIMENTAL) */
#define DNS_TYPE_MR 9      /* a mail rename domain name (EXPERIMENTAL) */
#define DNS_TYPE_NULL 10   /* a null RR (EXPERIMENTAL) */
#define DNS_TYPE_WKS 11    /* a well known service description */
#define DNS_TYPE_PTR 12    /* a domain name pointer */
#define DNS_TYPE_HINFO 13  /* host information */
#define DNS_TYPE_MINFO 14  /* mailbox or mail list information */
#define DNS_TYPE_MX 15     /* mail exchange */
#define DNS_TYPE_TXT 16    /* text strings */
#define DNS_QTYPE_AXFR 252   /* a request for a transfer of an entire zone */
#define DNS_QTYPE_MAILB 253  /* a request for mailbox-related records (MB, MG or MR) */
#define DNS_QTYPE_MAILA 254  /* a request for mail agent RRs (Obsolete - see MX) */
#define DNS_QTYPE_STAR 255   /* a request for all records */

/* DNS classes */
#define DNS_CLASS_IN 1      /* the Internet */
#define DNS_CLASS_CS 2      /* the CSNET class (Obsolete - used only for examples in
                               obsolete RFCs) */
#define DNS_CLASS_CH 3      /* the CHAOS class */
#define DNS_CLASS_HS 4      /* Hesiod */
#define DNS_QCLASS_STAR 255 /* any class */

enum udp_app {
    UNKNOWN,
    DNS,
    SNMP,
    RIP,
    DHCP
};

struct arp_info {
    char sip[INET_ADDRSTRLEN]; /* sender IP address */
    char tip[INET_ADDRSTRLEN]; /* target IP address */
    char sha[HW_ADDRSTRLEN];   /* sender hardware address */
    char tha[HW_ADDRSTRLEN];   /* target hardware address */
    uint16_t op;               /* ARP opcode */
};

struct dns_info {
    unsigned int qr     : 1; /* 0 DNS query, 1 DNS response */
    unsigned int opcode : 4;
    unsigned int aa     : 1;
    unsigned int rcode  : 4;

    /* question section */
    struct {
        char qname[DNS_NAMELEN];
        uint16_t qtype;  /* QTYPES are a superset of TYPES */
        uint16_t qclass; /* QCLASS values are a superset of CLASS values */
    } question;

    /* answer section */
    struct resource_record {
        /* a domain name to which the resource record pertains */
        char name[DNS_NAMELEN];
        uint16_t type;
        uint16_t class;
        /*
         * Specifies the time interval (in seconds) that the resource record
         * may be cached before it should be discarded.  Zero values are
         * interpreted to mean that the RR can only be used for the
         * transaction in progress, and should not be cached. */
        uint32_t ttl;
        /*
         * The format of rdata varies according to the type and class of the
         * resource record.
         */
        union {
            /* a domain name which specifies the canonical or primary name
               for the owner. The owner name is an alias. */
            char cname[DNS_NAMELEN];
            /* a domain name which points to some location in the domain
               name space. */
            char ptrdname[DNS_NAMELEN];
            uint32_t address; /* a 32 bit internet address */
        } rdata;
    } answer;
};

// TODO: Improve the structure of this
struct ip_info {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    uint8_t protocol;
    union {
        struct {
            uint16_t src_port;
            uint16_t dst_port;
            uint8_t utype; /* specifies the protocol carried in the UDP packet */
            // TODO: Should be made into a pointer
            struct dns_info dns;
        } udp;
        struct {
            uint16_t src_port;
            uint16_t dst_port;
        } tcp;
        struct {
            uint8_t type;
            uint8_t max_resp_time;
            char group_addr[INET_ADDRSTRLEN];
        } igmp;
    };
};

/* get a packet from the network interface card */
void read_packet(int sockfd);

#endif
