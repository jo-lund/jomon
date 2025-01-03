#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "packet_ip.h"
#include "jomon.h"

/*
 * IP Differentiated Services Code Point class selectors.
 * Prior to DiffServ, IPv4 networks could use the Precedence field in the TOS
 * byte of the IPv4 header to mark priority traffic. In order to maintain
 * backward compatibility with network devices that still use the Precedence
 * field, DiffServ defines the Class Selector PHB.
 *
 * The Class Selector code points are of the form 'xxx000'. The first three bits
 * are the IP precedence bits. Each IP precedence value can be mapped into a
 * DiffServ class. CS0 equals IP precedence 0, CS1 IP precedence 1, and so on.
 * If a packet is received from a non-DiffServ aware router that used IP
 * precedence markings, the DiffServ router can still understand the encoding as
 * a Class Selector code point.
 */
#define CS0 0X0
#define CS1 0X8
#define CS2 0X10
#define CS3 0X18
#define CS4 0X20
#define CS5 0X28
#define CS6 0X30
#define CS7 0X38

#define MIN_HEADER_LEN 20

extern void add_ipv4_information(void *w, void *sw, void *data);
extern void print_ipv4(char *buf, int n, void *data);
static packet_error handle_ipv4(struct protocol_info *pinfo, unsigned char *buffer, int n,
                                struct packet_data *pdata);

static struct packet_flags ipv4_flags[] = {
    { "Reserved", 1, NULL },
    { "Don't Fragment", 1, NULL },
    { "More Fragments", 1, NULL }
};

static char *copied_flag[] = {
    "Not copied into all fragments",
    "Copied into all fragments"
};

static char *option_class[] = {
    "Control",
    "Reserved",
    "Debugging and measurement",
    "Reserved"
};

static char *option_number[32] = {
    [IP_OPT_END]       = "End of option list",
    [IP_OPT_NOP]       = "No operation",
    [IP_OPT_SECURITY]  = "Security",
    [IP_OPT_LSR]       = "Loose Source Routing",
    [IP_OPT_TIMESTAMP] = "Timestamp",
    [IP_OPT_RR]        = "Record Route",
    [IP_OPT_STREAM_ID] = "Stream ID",
    [IP_OPT_SSR]       = "Strict Source Routing",
    [IP_OPT_ROUTER_ALERT] = "Router Alert"
};

static struct packet_flags opt_flags[] = {
    { "Copied flag:", 1, copied_flag },
    { "Option class:", 2, option_class },
    { "Option number:", 5, option_number },
};

static struct protocol_info ipv4_prot = {
    .short_name = "IPv4",
    .long_name = "Internet Protocol Version 4",
    .decode = handle_ipv4,
    .print_pdu = print_ipv4,
    .add_pdu = add_ipv4_information
};

void register_ip(void)
{
    register_protocol(&ipv4_prot, ETHERNET_II, ETHERTYPE_IP);
    register_protocol(&ipv4_prot, IP4_PROT, IPPROTO_IPIP);
    register_protocol(&ipv4_prot, PKT_LOOP, ETHERTYPE_IP);
}

static packet_error parse_options(struct ipv4_info *ip, unsigned char **buf, int n)
{
    struct ipv4_options **opt;
    unsigned char *p = *buf;
    int nelem;

    opt = &ip->opt;
    while (n > 0) {
        *opt = mempool_alloc(sizeof(*ip->opt));
        (*opt)->type = p[0];
        switch (GET_IP_OPTION_NUMBER((*opt)->type)) {
        case IP_OPT_END:
            *buf = ++p;
            (*opt)->length = 1;
            (*opt)->next = NULL;
            return NO_ERR;
        case IP_OPT_NOP:
            p++;
            n--;
            break;
        case IP_OPT_SECURITY:
            if (n < 2 || ((*opt)->length = p[1]) < 2)
                goto error;
            p += 2;
            n -= 2;
            if ((*opt)->length != 11 || n < (*opt)->length - 2)
                goto error;
            (*opt)->security.security = read_uint16be(&p);
            (*opt)->security.compartments = read_uint16be(&p);
            (*opt)->security.restrictions = read_uint16be(&p);
            (*opt)->security.tcc = p[0] << 16 | p[1] << 8 | p[2];
            p += 3; /* 3 bytes tcc field */
            n -= ((*opt)->length - 2);
            break;
        case IP_OPT_LSR:
        case IP_OPT_RR:
        case IP_OPT_SSR:
            if (n < 2 || ((*opt)->length = p[1]) < 2)
                goto error;
            p += 2;
            n -= 2;
            if ((((*opt)->length - 3) & 3) != 0 || (*opt)->length < 7 || n < (*opt)->length - 2)
                goto error;
            (*opt)->route.pointer = p[0];
            p++;
            n--;
            nelem = ((*opt)->length - 3) / 4;
            (*opt)->route.route_data = mempool_alloc(nelem * 4);
            n = parse_ipv4_addr((*opt)->route.route_data, nelem, &p, n);
            break;
        case IP_OPT_TIMESTAMP:
            if (n < 2 || ((*opt)->length = p[1]) < 2)
                goto error;
            p += 2;
            n -= 2;
            if (n < (*opt)->length - 2 || (*opt)->length < 8)
                goto error;
            (*opt)->timestamp.pointer = p[0];
            (*opt)->timestamp.oflw = (p[1] & 0xf0) >> 4;
            (*opt)->timestamp.flg = p[1] & 0x0f;
            if ((((*opt)->length - 4) & 3) != 0)
                goto error;
            switch ((*opt)->timestamp.flg) {
            case IP_TS_ONLY:
                (*opt)->timestamp.ts.timestamp = mempool_copy(p, ((*opt)->length - 4) / 4);
                break;
            case IP_TS_ADDR:
            case IP_TS_PRESPECIFIED:
                nelem = ((*opt)->length - 4) / 8;
                if (nelem == 0 || n < 8)
                    goto error;
                (*opt)->timestamp.ts.timestamp = mempool_alloc(nelem * 4);
                (*opt)->timestamp.ts.addr = mempool_alloc(nelem * 4);
                for (int i = 0; i < nelem && n >= 8; i++) {
                    memcpy((*opt)->timestamp.ts.addr + i, p, 4);
                    memcpy((*opt)->timestamp.ts.timestamp + i, p + 4, 4);
                    p += 8;
                    n -= 8;
                }
                break;
            default:
                break;
            }
            break;
        case IP_OPT_STREAM_ID:
            if (n < 2 || ((*opt)->length = p[1]) < 2)
                goto error;
            p += 2;
            n -= 2;
            if (n < 2 || (*opt)->length != 4)
                goto error;
            (*opt)->stream_id = read_uint16be(&p);
            n -= 2;
            break;
        case IP_OPT_ROUTER_ALERT:
            if (n < 2 || ((*opt)->length = p[1]) < 2)
                goto error;
            p += 2;
            n -= 2;
            if (n < 2 || (*opt)->length != 4)
                goto error;
            (*opt)->router_alert = read_uint16be(&p);
            n -= 2;
            break;
        default:
            if (n < 2 || ((*opt)->length = p[1]) < 2)
                goto error;
            p += 2;
            n -= 2;
            DEBUG("IP option %d not supported", (*opt)->type);
            if ((*opt)->length - 2 > n)
                goto error;
            p += ((*opt)->length - 2);
            n -= ((*opt)->length - 2);
            break;
        }
        opt = &(*opt)->next;
    }
    *buf = p;
    *opt = NULL;
    return NO_ERR;

error:
    if (*opt) {
        mempool_free(*opt);
        *opt = NULL;
    }
    return DECODE_ERR;
}

/*
 * IPv4 header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * IHL: Internet header length, the number of 32 bit words in the header.
 *      The minimum value for this field is 5: 5 * 32 = 160 bits (20 bytes).
 * Flags: Used to control and identify fragments
 *        Bit 0: Reserved, must be zero
 *        Bit 1: Don't Fragment (DF)
 *        Bit 2: More Fragments (MF)
 * Fragment offset: Specifies the offset of a particular fragment relative to
 * the beginning of the unfragmented IP datagram. The first fragment has an
 * offset of zero.
 * Protocol: Defines the protocol used in the data portion of the packet.
 */
packet_error handle_ipv4(struct protocol_info *pinfo, unsigned char *buffer, int n,
                         struct packet_data *pdata)
{
    unsigned int header_len;
    struct ipv4_info *ipv4;
    uint32_t id;
    struct protocol_info *layer3;

    ipv4 = mempool_alloc(sizeof(struct ipv4_info));
    pdata->data = ipv4;
    if (n < MIN_HEADER_LEN) {
        memset(ipv4, 0, sizeof(*ipv4));
        pdata->len = n;
        pdata->error = create_error_string("Packet length (%d) less than IP header length (%d)",
                                           n, MIN_HEADER_LEN);
        return DECODE_ERR;
    }
    ipv4->version = (buffer[0] & 0xf0) >> 4;
    if (ipv4->version != 4)
        pdata->error = create_error_string("IP4 version error %d != 4", ipv4->version);
    ipv4->ihl = (buffer[0] & 0x0f);
    header_len = ipv4->ihl * 4;
    if ((unsigned int) n < header_len || ipv4->ihl < 5) {
        pdata->len = 0;
        ipv4->dscp = 0;
        ipv4->ecn = 0;
        ipv4->length = 0;
        ipv4->id = 0;
        ipv4->foffset = 0;
        ipv4->ttl = 0;
        ipv4->protocol = 0;
        ipv4->checksum = 0;
        ipv4->src = 0;
        ipv4->dst = 0;
        ipv4->opt = NULL;
        if ((unsigned int) n < header_len)
            pdata->error = create_error_string("Packet length (%d) less than IP Internet header length (%d)",
                                               n, ipv4->ihl * 4);
        else
            pdata->error = create_error_string("IP Internet header length (%u) is less than minimum value (5)",
                                               ipv4->ihl);
        return DECODE_ERR;
    }
    pdata->len = header_len;

    /* Originally defined as type of service, but now defined as differentiated
       services code point and explicit congestion control */
    ipv4->dscp = (buffer[1] & 0xfc) >> 2;
    ipv4->ecn = buffer[1] & 0x03;
    buffer += 2;
    ipv4->length = read_uint16be(&buffer);

    /* The packet has been padded in order to contain the minimum number of
       bytes. The padded bytes should be ignored. */
    if (n > ipv4->length)
        n = ipv4->length;

    ipv4->id = read_uint16be(&buffer);
    ipv4->foffset = read_uint16be(&buffer);
    ipv4->ttl = buffer[0];
    ipv4->protocol = buffer[1];
    buffer += 2;
    ipv4->checksum = read_uint16be(&buffer);
    ipv4->src = read_uint32le(&buffer);
    ipv4->dst = read_uint32le(&buffer);
    ipv4->opt = NULL;
    if (ipv4->ihl > 5) {
        if (parse_options(ipv4, &buffer, (ipv4->ihl - 5) * 4) != NO_ERR) {
            if (ipv4->opt) {
                mempool_free(ipv4->opt);
                ipv4->opt = NULL;
            }
            pdata->error = create_error_string("IP options error");
            return DECODE_ERR;
        }
    }
    if (ipv4->length < header_len) {
        pdata->error = create_error_string("IP total length (%d) less than header length (%d)",
                                           ipv4->length, header_len);
        return DECODE_ERR;
    }
    if (ipv4->length > n) {
        pdata->error = create_error_string("IP total length (%d) greater than packet length (%d)",
                                           ipv4->length, n);
        return DECODE_ERR;
    }
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    id = get_protocol_id(IP4_PROT, ipv4->protocol);
    layer3 = get_protocol(id);
    if (layer3) {
        pdata->next = mempool_calloc(1, struct packet_data);
        pdata->next->prev = pdata;
        pdata->next->id = id;
        if (layer3->decode(layer3, buffer, n - header_len, pdata->next) == UNK_PROTOCOL) {
            mempool_free(pdata->next);
            pdata->next = NULL;
        }
    }
    return NO_ERR;
}

char *get_ipv4_dscp(uint8_t dscp)
{
    switch (dscp) {
    case CS0:
        return "Default";
    case CS1:
        return "Class Selector 1";
    case CS2:
        return "Class Selector 2";
    case CS3:
        return "Class Selector 3";
    case CS4:
        return "Class Selector 4";
    case CS5:
        return "Class Selector 5";
    case CS6:
        return "Class Selector 6";
    default:
        return NULL;
    }
}

char *get_ip_transport_protocol(uint8_t protocol)
{
    switch (protocol) {
    case IPPROTO_ICMP:
        return "ICMP";
    case IPPROTO_IGMP:
        return "IGMP";
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_PIM:
        return "PIM";
    default:
        return NULL;
    }
}

struct packet_flags *get_ipv4_flags(void)
{
    return ipv4_flags;
}

int get_ipv4_flags_size(void)
{
    return ARRAY_SIZE(ipv4_flags);
}

struct packet_flags *get_ipv4_opt_flags(void)
{
    return opt_flags;
}

int get_ipv4_opt_flags_size(void)
{
    return ARRAY_SIZE(opt_flags);
}

uint16_t get_ipv4_foffset(struct ipv4_info *ip)
{
    return ip->foffset & 0x1fff;
}

int parse_ipv4_addr(uint32_t *addrs, int count, unsigned char **buf, int n)
{
    unsigned char *p = *buf;

    for (int i = 0; i < count && (unsigned int) n >= sizeof(uint32_t); i++) {
        *addrs++ = read_uint32le(&p); /* store in big-endian format */
        n -= sizeof(uint32_t);
    }
    *buf = p;
    return n;
}

char *get_ipv4_opt_type(uint8_t type)
{
    return option_number[GET_IP_OPTION_NUMBER(type)];
}

char *get_ipv4_security(uint16_t security)
{
    switch (security) {
    case IP_UNCLASSIFIED:
        return "Unclassified";
    case IP_CONFIDENTIAL:
        return "Confidential";
    case IP_EFTO:
        return "EFTO";
    case IP_MMMM:
        return "MMMM";
    case IP_PROG:
        return "PROG";
    case IP_SECRET:
        return "Secret";
    case IP_TOP_SECRET:
        return "Top Secret";
    default:
        return NULL;
    }
}

char *get_router_alert_option(uint16_t opt)
{
    if (opt == 0)
        return "Router shall examine packet";
    return "Reserved";
}
