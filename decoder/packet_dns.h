#ifndef PACKET_DNS_H
#define PACKET_DNS_H

#include <stdbool.h>
#include <stdint.h>

#define DNS_HDRLEN 12
#define DNS_NAMELEN 256 /* a DNS name is 255 bytes or less + null byte */

/* DNS opcodes */
#define DNS_QUERY 0  /* standard query */
#define DNS_IQUERY 1 /* inverse query */
#define DNS_STATUS 2 /* server status request */

/* DNS response codes */
#define DNS_NO_ERROR 0         /* no error condition */
#define DNS_FORMAT_ERROR 1     /* name server was unable to interpret the query */
#define DNS_SERVER_FAILURE 2   /* name server was unable to process the query */
#define DNS_NAME_ERROR 3       /* the domain name referenced in the query does not exist */
#define DNS_NOT_IMPLEMENTED 4  /* name server does not support the requested kind of query */
#define DNS_REFUSED 5          /* name server refuses to perform the specified operation */

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
#define DNS_TYPE_AAAA 28   /* a host IPv6 address */
#define DNS_TYPE_SRV 33    /* generalized service location */
#define DNS_TYPE_OPT 41    /* a pseudo record type needed to support EDNS */
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

typedef struct list list_t;
struct application_info;

/*
 * In the Resource Record Sections of a Multicast DNS response, the top
 * bit of the rrclass field is used to indicate the cache-flush bit.
 * This bit tells neighbouring hosts that this is not a shared record type.
 * Instead of merging this new record additively into the cache in addition to
 * any previous records with the same name, rrtype, and rrclass, all old records
 * with that name, rrtype, and rrclass that were received more than one second
 * ago are declared invalid, and marked to expire from the cache in one second.
 * cf. RFC 6762, section 10.2
 */
#define GET_MDNS_CACHE_FLUSH(rrclass) ((rrclass) & 0x8000)

/*
 * Multicast DNS defines the top bit in the class field of a DNS
 * question as the unicast-response bit. When this bit is set in a
 * question, it indicates that the querier is willing to accept unicast
 * replies in response to this specific query, as well as the usual
 * multicast responses.
 * cf RFC 6762, section 5.4
*/
#define GET_MDNS_UNICAST_RESPONSE(qclass) ((qclass) & 0x8000)

/* Get the rrclass proper from the MDNS rrclass field */
#define GET_MDNS_RRCLASS(rrclass) ((rrclass) & 0x7fff)

/*
 * OPT Record TTL Field Use:
 *
 * Forms the upper 8 bits of extended 12-bit RCODE. Note that EXTENDED-RCODE
 * value 0 indicates that an unextended RCODE is in use (values 0 through 15).
 */
#define GET_DNS_OPT_EXTENDED_RCODE(ttl) ((ttl) & 0xff000000)

/* indicates the implementation level of the setter */
#define GET_DNS_OPT_VERSION(ttl) ((ttl) & 0x00ff0000)

/* DNSSEC OK bit as defined by RFC3225 */
#define GET_DNS_OPT_D0(ttl) ((ttl) & 0x00008000)

enum dns_section_count {
    QDCOUNT,
    ANCOUNT,
    NSCOUNT,
    ARCOUNT
};

struct dns_txt_rr {
    int len;
    char *txt;
};

struct dns_opt_rr {
    uint16_t option_code;
    uint16_t option_length;
    unsigned char *data;
};

// TODO: Clean up this structure
struct dns_info {
    uint16_t id; /* A 16 bit identifier */
    unsigned int qr     : 1; /* 0 DNS query, 1 DNS response */
    unsigned int opcode : 4; /* specifies the kind of query in the message */
    unsigned int aa     : 1; /* authoritative answer */
    unsigned int tc     : 1; /* truncation - specifies that the message was truncated */
    unsigned int rd     : 1; /* recursion desired - if set it directs the name server
                                to pursue the query recursively */
    unsigned int ra     : 1; /* recursion avilable - denotes whether recursive query
                                support is available in the name server */
    unsigned int rcode  : 4; /* response code */
    unsigned int section_count[4];

    /* question section */
    struct {
        char qname[DNS_NAMELEN];
        uint16_t qtype;  /* QTYPES are a superset of TYPES */
        uint16_t qclass; /* QCLASS values are a superset of CLASS values */
    } question;

    /* answer/authority/additional section */
    struct dns_resource_record {
        /* a domain name to which the resource record pertains */
        char name[DNS_NAMELEN];
        uint16_t type;
        uint16_t rrclass;
        /*
         * Specifies the time interval (in seconds) that the resource record
         * may be cached before it should be discarded. Zero values are
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
            /* a domain name which specifies a host which should be
               authoritative for the specified class and domain */
            char nsdname[DNS_NAMELEN];
            uint32_t address; /* a 32 bit IPv4 internet address */
            uint8_t ipv6addr[16]; /* a 128 bit IPv6 address */

             /* start of authority */
            struct {
                /* the domain name of the name server that was the
                   original or primary source of data for this zone */
                char mname[DNS_NAMELEN];
                /* a domain name which specifies the mailbox of the
                   person responsible for this zone */
                char rname[DNS_NAMELEN];
                uint32_t serial; /* the version number of the original copy of the zone */

                /* all times are in units of seconds */
                int32_t refresh;  /* time interval before the zone should be refreshed */
                int32_t retry;    /* time interval that should elapse before a
                                     failed refresh should be retried */
                int32_t expire;   /* time value that specifies the upper limit on
                                     the time interval that can elapse before the
                                     zone is no longer authoritative */
                uint32_t minimum; /* the minimum ttl field that should be exported
                                     with any RR from this zone */
            } soa;

            /*
             * HINFO records are used to acquire general information about a
             * host. It contains CPU, a string which specifies the CPU type,
             * and OS, a string which specifies the operating system type.
             *
             * RFC 1032 says that CPU and OS are character strings. No
             * explanation on how the strings are formatted, but in practice they
             * contain one byte length field followed by that number of bytes.
             */
            struct {
                char *cpu;
                char *os;
            } hinfo;

            /*
             * TXT RRs are used to hold descriptive text.
             *
             * According to RFC 1032 txt_data can contain one or more character
             * strings. The strings are formatted as one byte length field
             * followed by that number of bytes.
             */
            list_t *txt;

            struct {
                /* specifies the preference given to this RR among others at the
                   same owner */
                uint16_t preference;
                /* a domain name that specifies a host willing to act as a mail
                   exchange for the owner name */
                char exchange[DNS_NAMELEN];
            } mx;

            struct {
                uint16_t priority; /* priority of this target host */
                uint16_t port;
                uint16_t weight; /* specifies a relative weight for entries with
                                    the same priority */
                char target[DNS_NAMELEN]; /* domain name of the target host */
            } srv;

            struct {
                uint16_t rdlen;
                unsigned char *data;
            } opt;

        } rdata;
    } *record;
};

char *get_dns_opcode(uint8_t opcode);
char *get_dns_rcode(uint8_t rcode);
char *get_dns_type(uint16_t type);
char *get_dns_type_extended(uint16_t type);
char *get_dns_class(uint16_t rrclass);
char *get_dns_class_extended(uint16_t rrclass);

/*
 * Get the size of the longest domain name in the RRs.
 * 'n' is the number of records
 */
int get_dns_max_namelen(struct dns_resource_record *record, int n);

/*
 * Parse the DNS pseudo opt resource record. The list needs to be freed with
 * free_dns_option
 */
list_t *parse_dns_options(struct dns_resource_record *rr);
void free_dns_options(list_t *opt);

/* internal to the decoder */
bool handle_dns(unsigned char *buffer, int n, struct application_info *info);
int parse_dns_name(unsigned char *buffer, int n, unsigned char *ptr, char name[]);
void free_dns_packet(struct dns_info *dns);

#endif
