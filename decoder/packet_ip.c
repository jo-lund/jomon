#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include "packet_ip.h"
#include "packet.h"
#include "jomon.h"
#include "field.h"

#define IP_OPT_END 0
#define IP_OPT_NOP 1
#define IP_OPT_SECURITY 2
#define IP_OPT_LSR 3  /* loose source routing */
#define IP_OPT_TIMESTAMP 4
#define IP_OPT_RR 7   /* record route */
#define IP_OPT_STREAM_ID 8
#define IP_OPT_SSR 9  /* strict source routing */
#define IP_OPT_ROUTER_ALERT 20
#define GET_IP_OPTION_NUMBER(t) ((t) & 0x1f)

#define IP_TS_ONLY 0
#define IP_TS_ADDR 1
#define IP_TS_PRESPECIFIED 3
#define IP_STANDARD_TS(ts) (((ts) & 0x80000000) == 0)

#define IP_UNCLASSIFIED 0
#define IP_CONFIDENTIAL 0xf135
#define IP_EFTO  0x789a
#define IP_MMMM 0xbc4d
#define IP_PROG 0x5e26
#define IP_SECRET 0xd788
#define IP_TOP_SECRET 0x6bc5

#define MIN_HEADER_LEN 20

static void print_ipv4(char *buf, int n, struct packet_data *pdata);
static packet_error handle_ipv4(struct protocol_info *pinfo, unsigned char *buf, int n,
                                struct packet_data *pdata);
static packet_error handle_ipn(struct protocol_info *pinfo, unsigned char *buf, int n,
                               struct packet_data *pdata);

/* Get the string representation of the options fields */
static char *get_ipv4_security(uint16_t security);

/* Get the string representation of the option's type */
static char *get_ipv4_opt_type(uint8_t type);

/* Get the string representation of the router alert option value */
static char *get_router_alert_option(uint16_t opt);

static char *set[] = { "Not set", "Set" };

static struct packet_flags ipv4_flags[] = {
    { "Reserved", 1, set },
    { "Don't Fragment", 1, set },
    { "More Fragments", 1, set }
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
    { "Copied flag", 1, copied_flag },
    { "Option class", 2, option_class },
    { "Option number", 5, option_number },
};

static struct packet_flags header[] = {
    { "Version", 4, NULL },
    { "Internet Header Length (IHL)", 4, NULL },
};

static char *dscp[48] = {
    [CS0] = "Default",
    [CS1] = "Class Selector 1",
    [CS2] = "Class Selector 2",
    [CS3] = "Class Selector 3",
    [CS4] = "Class Selector 4",
    [CS5] = "Class Selector 5",
};

static char *ecn[] = {
    "Not ECN-Capable",
    "ECT(1)",
    "ECT(0)",
    "CE",
};

static struct packet_flags tos[] = {
    { "Differentiated Services Code Point (DSCP)", 6, dscp },
    { "Explicit Congestion Notification (ECN)", 2, ecn },
};

static struct packet_flags timestamp[] = {
    { "Overflow", 4, NULL },
    { "Flags", 4, NULL },
};

static struct protocol_info ipv4 = {
    .short_name = "IPv4",
    .long_name = "Internet Protocol Version 4",
    .decode = handle_ipv4,
    .print_pdu = print_ipv4,
};

static struct protocol_info ip_raw = {
    .short_name = "Raw",
    .long_name = "Raw IP",
    .decode = handle_ipn,
    .print_pdu = NULL,
};

void register_ip(void)
{
    register_protocol(&ipv4, ETHERNET_II, ETHERTYPE_IP);
    register_protocol(&ipv4, IP4_PROT, IPPROTO_IPIP);
    register_protocol(&ipv4, PKT_LOOP, ETHERTYPE_IP);
    register_protocol(&ipv4, PKT_RAW, ETHERTYPE_IP);
    register_protocol(&ip_raw, DATALINK, LINKTYPE_RAW);
}

static packet_error parse_options(struct packet_data *pdata, unsigned char **buf, int n)
{
    unsigned char *p = *buf;
    int nelem;
    uint8_t type, length;

    while (n > 0) {
        type = p[0];
        switch (GET_IP_OPTION_NUMBER(type)) {
        case IP_OPT_END:
            field_add_value(pdata->data, "IP Option", FIELD_STRING_HEADER, get_ipv4_opt_type(type));
            field_add_bitfield(pdata->data, "Type", type, false, opt_flags, ARRAY_SIZE(opt_flags));
            length = 1;
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            *buf = ++p;
            return NO_ERR;
        case IP_OPT_NOP:
            p++;
            n--;
            break;
        case IP_OPT_SECURITY:
        {
            struct uint_string security;

            if (n < 2 || (length = p[1]) < 2)
                return DECODE_ERR;
            p += 2;
            n -= 2;
            if (length != 11 || n < length - 2)
                return DECODE_ERR;
            field_add_value(pdata->data, "IP Option", FIELD_STRING_HEADER, get_ipv4_opt_type(type));
            field_add_bitfield(pdata->data, "Type", type, false, opt_flags, ARRAY_SIZE(opt_flags));
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            security.val = read_uint16be(&p);
            security.str = get_ipv4_security(security.val);
            field_add_value(pdata->data, "Security", FIELD_UINT_STRING, &security);
            field_add_value(pdata->data, "Compartments", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&p)));
            field_add_value(pdata->data, "Handling restrictions", FIELD_UINT16,
                            UINT_TO_PTR(read_uint16be(&p)));
            field_add_value(pdata->data, "Transmission Control Code (TCC)", FIELD_UINT16,
                            UINT_TO_PTR(p[0] << 16 | p[1] << 8 | p[2]));
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            p += 3; /* 3 bytes tcc field */
            n -= (length - 2);
            break;
        }
        case IP_OPT_LSR:
        case IP_OPT_RR:
        case IP_OPT_SSR:
            if (n < 2 || (length = p[1]) < 2)
                return DECODE_ERR;
            p += 2;
            n -= 2;
            if (((length - 3) & 3) != 0 || length < 7 || n < length - 2)
                return DECODE_ERR;
            field_add_value(pdata->data, "IP Option", FIELD_STRING_HEADER, get_ipv4_opt_type(type));
            field_add_bitfield(pdata->data, "Type", type, false, opt_flags, ARRAY_SIZE(opt_flags));
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            field_add_value(pdata->data, "Pointer", FIELD_UINT8, UINT_TO_PTR(p[0]));
            p++;
            n--;
            nelem = (length - 3) / 4;
            for (int i = 0; i < nelem && (unsigned int) n >= sizeof(uint32_t); i++) {
                field_add_value(pdata->data, "Route data", FIELD_IP4ADDR,
                                UINT_TO_PTR(read_uint32le(&p)));
                n -= sizeof(uint32_t);
            }
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            break;
        case IP_OPT_TIMESTAMP:
        {
            uint8_t flags;

            if (n < 2 || (length = p[1]) < 2)
                return DECODE_ERR;
            p += 2;
            n -= 2;
            if (n < length - 2 || length < 8)
                return DECODE_ERR;
            field_add_value(pdata->data, "IP Option", FIELD_STRING_HEADER, get_ipv4_opt_type(type));
            field_add_bitfield(pdata->data, "Type", type, false, opt_flags, ARRAY_SIZE(opt_flags));
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            field_add_value(pdata->data, "Pointer", FIELD_UINT8, UINT_TO_PTR(p[0]));
            p++;
            n--;
            flags = p[0] & 0x0f;
            field_add_bitfield(pdata->data, "", p[0], true, timestamp, ARRAY_SIZE(timestamp));
            p++;
            n--;
            if (((length - 4) & 3) != 0)
                return DECODE_ERR;
            switch (flags) {
            case IP_TS_ONLY:
                nelem = (length - 4) / 8;
                for (int i = 0; i < nelem && (unsigned int) n >= sizeof(uint32_t); i++) {
                    uint32_t ts;

                    ts = read_uint32be(&p);
                    if (IP_STANDARD_TS(ts))
                        field_add_value(pdata->data, "Timestamp", FIELD_TIMESTAMP,
                                        UINT_TO_PTR(read_uint32be(&p)));
                    else
                        field_add_value(pdata->data, "Timestamp", FIELD_TIMESTAMP_NON_STANDARD,
                                        UINT_TO_PTR(read_uint32be(&p)));
                    n -= 4;
                }
                break;
            case IP_TS_ADDR:
            case IP_TS_PRESPECIFIED:
                nelem = (length - 4) / 8;
                if (nelem == 0 || n < 8)
                    return DECODE_ERR;
                for (int i = 0; i < nelem && n >= 8; i++) {
                    uint32_t ts;

                    ts = read_uint32be(&p);
                    if (IP_STANDARD_TS(ts))
                        field_add_value(pdata->data, "Timestamp", FIELD_TIMESTAMP,
                                        UINT_TO_PTR(read_uint32be(&p)));
                    else
                        field_add_value(pdata->data, "Timestamp", FIELD_TIMESTAMP_NON_STANDARD,
                                        UINT_TO_PTR(read_uint32be(&p)));
                    field_add_value(pdata->data, "Route data", FIELD_IP4ADDR,
                                    UINT_TO_PTR(read_uint32le(&p)));
                    n -= 8;
                }
                break;
            default:
                break;
            }
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            break;
        }
        case IP_OPT_STREAM_ID:
            if (n < 2 || (length = p[1]) < 2)
                return DECODE_ERR;
            p += 2;
            n -= 2;
            if (n < 2 || length != 4)
                return DECODE_ERR;
            field_add_value(pdata->data, "IP Option", FIELD_STRING_HEADER, get_ipv4_opt_type(type));
            field_add_bitfield(pdata->data, "Type", type, false, opt_flags, ARRAY_SIZE(opt_flags));
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            field_add_value(pdata->data, "Stream ID", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&p)));
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            n -= 2;
            break;
        case IP_OPT_ROUTER_ALERT:
        {
            uint16_t router_alert;

            if (n < 2 || (length = p[1]) < 2)
                return DECODE_ERR;
            p += 2;
            n -= 2;
            if (n < 2 || length != 4)
                return DECODE_ERR;
            field_add_value(pdata->data, "IP Option", FIELD_STRING_HEADER, get_ipv4_opt_type(type));
            field_add_bitfield(pdata->data, "Type", type, false, opt_flags, ARRAY_SIZE(opt_flags));
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            router_alert = read_uint16be(&p);
            field_add_value(pdata->data, get_router_alert_option(router_alert), FIELD_UINT16,
                            UINT_TO_PTR(router_alert));
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            n -= 2;
            break;
        }
        default:
            if (n < 2 || (length = p[1]) < 2)
                return DECODE_ERR;
            p += 2;
            n -= 2;
            DEBUG("IP option %d not supported", type);
            if (length - 2 > n)
                return DECODE_ERR;
            p += (length - 2);
            n -= (length - 2);
            break;
        }
    }
    *buf = p;
    return NO_ERR;
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
packet_error handle_ipv4(struct protocol_info *pinfo, unsigned char *buf, int n,
                         struct packet_data *pdata)
{
    unsigned int header_len;
    uint32_t id;
    struct protocol_info *layer3;
    uint8_t version, ihl;
    uint16_t length;
    uint16_t offset;
    struct uint_string protocol;

    if (n < MIN_HEADER_LEN) {
        pdata->error = create_error_string("Packet length (%d) less than IP header length (%d)",
                                           n, MIN_HEADER_LEN);
        return DECODE_ERR;
    }
    version = (buf[0] & 0xf0) >> 4;
    if (version != 4) {
        pdata->error = create_error_string("IP4 version error %d != 4", version);
        return DECODE_ERR;
    }
    ihl = (buf[0] & 0x0f);
    header_len = ihl * 4;
    if ((unsigned int) n < header_len) {
        pdata->error = create_error_string("Packet length (%d) less than IP Internet header length (%d)",
                                           n, ihl * 4);
        return DECODE_ERR;
    }
    if (ihl < 5) {
        pdata->error = create_error_string("IP Internet header length (%u) is less than minimum value (5)", ihl);
        return DECODE_ERR;
    }
    pdata->data = field_init();
    field_add_bitfield(pdata->data, "", buf[0], true, header, ARRAY_SIZE(header));
    buf++;

    /* Originally defined as type of service, but now defined as differentiated
       services code point and explicit congestion control */
    field_add_bitfield(pdata->data, "Differentiated services field",
                           buf[0], false, tos, ARRAY_SIZE(tos));
    buf++;
    length = read_uint16be(&buf);
    field_add_value(pdata->data, "Total length", FIELD_UINT16, UINT_TO_PTR(length));

    /* The packet has been padded in order to contain the minimum number of
       bytes. The padded bytes should be ignored. */
    if (n > length)
        n = length;

    field_add_value(pdata->data, "Identification", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buf)));

    /* the 3 first bits are flags */
    field_add_bitfield(pdata->data, "Flags", buf[0] >> 5, false, ipv4_flags, ARRAY_SIZE(ipv4_flags));
    offset = read_uint16be(&buf) & 0x1fff; /* clear the flag bits */
    field_add_value(pdata->data, "Fragment offset", FIELD_UINT16_HEX, UINT_TO_PTR(offset));
    field_add_value(pdata->data, "Time to live", FIELD_UINT8, UINT_TO_PTR(buf[0]));
    buf++;
    protocol.val = buf[0];
    protocol.str = get_ip_transport_protocol(protocol.val);
    field_add_value(pdata->data, "Protocol", FIELD_UINT_STRING, &protocol);
    buf++;
    field_add_value(pdata->data, "Checksum", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buf)));
    field_add_value(pdata->data, "Source IP Address", FIELD_IP4ADDR,
                    UINT_TO_PTR(read_uint32le(&buf)));
    field_add_value(pdata->data, "Destination IP Address", FIELD_IP4ADDR,
                    UINT_TO_PTR(read_uint32le(&buf)));
    if (ihl > 5) {
        if (parse_options(pdata, &buf, (ihl - 5) * 4) != NO_ERR) {
            field_finish(pdata->data);
            pdata->error = create_error_string("IP options error");
            return DECODE_ERR;
        }
    }
    if (length < header_len) {
        field_finish(pdata->data);
        pdata->error = create_error_string("IP total length (%d) less than header length (%d)",
                                           length, header_len);
        return DECODE_ERR;
    }
    if (length > n) {
        field_finish(pdata->data);
        pdata->error = create_error_string("IP total length (%d) greater than packet length (%d)",
                                           length, n);
        return DECODE_ERR;
    }
    field_finish(pdata->data);
    pdata->len = header_len;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    id = get_protocol_id(IP4_PROT, protocol.val);
    layer3 = get_protocol(id);
    if (layer3) {
        pdata->next = mempool_calloc(1, struct packet_data);
        pdata->next->id = id;
        if (layer3->decode(layer3, buf, n - header_len, pdata->next) == UNK_PROTOCOL) {
            mempool_free(pdata->next);
            pdata->next = NULL;
        }
    }
    return NO_ERR;
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
    case IPPROTO_ICMPV6:
        return "ICMP6";
    default:
        return "Unknown";
    }
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

packet_error handle_ipn(struct protocol_info *pinfo UNUSED, unsigned char *buf, int n,
                         struct packet_data *pdata)
{
    uint8_t version;
    struct protocol_info *raw = NULL;

    if (n < 1)
        return DATALINK_ERR;

    version = (buf[0] & 0xf0) >> 4;
    if (version == 4) {
        pdata->id = get_protocol_id(PKT_RAW, ETHERTYPE_IP);
        raw = get_protocol(pdata->id);
    } else if (version == 6) {
        pdata->id = get_protocol_id(PKT_RAW, ETHERTYPE_IPV6);
        raw = get_protocol(pdata->id);
    }
    if (raw) {
        raw->decode(raw, buf, n, pdata);
        return NO_ERR;
    }
    return DECODE_ERR;
}

static void print_ipv4(char *buf, int n, struct packet_data *pdata)
{
    struct uint_string *protocol;

    protocol = field_search_value(pdata->data, "Protocol");
    snprintf(buf, n, "Next header: %u", protocol->val);
}

uint32_t ipv4_src(const struct packet *p)
{
    struct packet_data *pdata;

    pdata = p->root;
    if (pdata->next && is_ipv4(pdata->next)) {
        const struct field *f = field_search(pdata->next->data, "Source IP Address");
        return field_get_uint32(f);
    }
    return 0;
}

uint32_t ipv4_dst(const struct packet *p)
{
    struct packet_data *pdata;

    pdata = p->root;
    if (pdata->next && is_ipv4(pdata->next)) {
        const struct field *f = field_search(pdata->next->data, "Destination IP Address");
        return field_get_uint32(f);
    }
    return 0;
}

bool is_ipv4(struct packet_data *pdata)
{
    struct protocol_info *pinfo = get_protocol(pdata->id);
    return strcmp(pinfo->short_name, "IPv4") == 0;
}
