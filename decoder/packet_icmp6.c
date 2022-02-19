#include <stdint.h>
#include <sys/types.h>
#include <netinet/icmp6.h>
#include "packet_icmp6.h"
#include "packet_ip.h"
#include "attributes.h"
#include "util.h"

#define ICMP6_HDR_LEN 8
#define PARSE_IP6ADDR(addr, buf, n) \
    do {                            \
        memcpy(addr, buf, 16);      \
        buf += 16;                  \
        n -= 16;                    \
    } while (0);

static packet_error handle_icmp6(struct protocol_info *pinfo, unsigned char *buf, int n,
                                 struct packet_data *pdata);
extern void add_icmp6_information(void *w, void *sw, void *data);
extern void print_icmp6(char *buf, int n, void *data);

static struct packet_flags router_adv_flags[] = {
    { "Managed address configuration", 1, NULL },
    { "Other configuration", 1, NULL },
};

static struct packet_flags prefix_info[] = {
    { "On-link", 1, NULL },
    { "Autonomous address-configuration", 1, NULL },
};

static struct packet_flags neigh_adv_flags[] = {
    { "Router", 1, NULL },
    { "Solicited", 1, NULL },
    { "Override", 1, NULL }
};

static struct protocol_info icmp6_prot = {
    .short_name = "ICMP6",
    .long_name = "Internet Control Message Protocol 6",
    .decode = handle_icmp6,
    .print_pdu = print_icmp6,
    .add_pdu = add_icmp6_information
};

void register_icmp6(void)
{
    register_protocol(&icmp6_prot, IP_PROTOCOL, IPPROTO_ICMPV6);
}

static int parse_linkaddr(uint8_t **addr, int len, unsigned char **buf)
{
    *addr = mempool_alloc(len);
    memcpy(*addr, *buf, len);
    *buf += len * 8;
    return len * 8;
}

static packet_error parse_data(struct packet_data *pdata, unsigned char *buf, int n)
{
    struct protocol_info *pinfo;
    uint32_t id;

    id = get_protocol_id(ETHERNET_II, ETHERTYPE_IPV6);
    pinfo = get_protocol(id);
    pdata->next = mempool_calloc(struct packet_data);
    pdata->next->id = id;
    return pinfo->decode(pinfo, buf, n, pdata->next);
}

static packet_error parse_options(struct icmp6_info *icmp6, struct packet_data *pdata,
                                  unsigned char *buf, int n)
{
    struct icmp6_option **opt = &icmp6->option;

    while (n > 0) {
        *opt = mempool_alloc(sizeof(*icmp6->option));
        (*opt)->next = NULL;
        (*opt)->type = buf[0];
        (*opt)->length = buf[1];
        buf += 2;
        switch ((*opt)->type) {
        case ND_OPT_SOURCE_LINKADDR:
            if ((*opt)->length * 8 > n)
                return DECODE_ERR;
            n -= parse_linkaddr(&(*opt)->source_addr, (*opt)->length * 8 - 2, &buf) - 2;
            break;
        case ND_OPT_TARGET_LINKADDR:
            if ((*opt)->length * 8 > n)
                return DECODE_ERR;
            n -= parse_linkaddr(&(*opt)->target_addr, (*opt)->length * 8 - 2, &buf) - 2;
            break;
        case ND_OPT_PREFIX_INFORMATION:
            if ((*opt)->length != 4 && (*opt)->length * 8 > n)
                return DECODE_ERR;
            (*opt)->prefix_info.prefix_length = buf[3];
            (*opt)->prefix_info.l = (buf[4] & 0x80) >> 7;
            (*opt)->prefix_info.a = (buf[4] & 0x40) >> 6;
            buf += 2;
            (*opt)->prefix_info.valid_lifetime = read_uint32be(&buf);
            (*opt)->prefix_info.pref_lifetime =  read_uint32be(&buf);
            buf += 4; /* skip reserved bytes */
            if ((*opt)->prefix_info.prefix_length > n)
                return DECODE_ERR;
            (*opt)->prefix_info.prefix = mempool_copy(buf, (*opt)->prefix_info.prefix_length);
            buf += (*opt)->prefix_info.prefix_length;
            n -= (*opt)->prefix_info.prefix_length;
            break;
        case ND_OPT_MTU:
            buf += 2; /* skip reserved bytes */
            if ((*opt)->length != 1 && n < 8)
                return DECODE_ERR;
            (*opt)->mtu = read_uint32be(&buf);
            n -= 8;
            break;
        case ND_OPT_REDIRECTED_HEADER:
            if (n < 6)
                return DECODE_ERR;
            buf += 6;  /* skip reserved bytes */
            n -= 6;
            return parse_data(pdata, buf, n);
        default:
            n -= (*opt)->length * 8;
            buf += (*opt)->length * 8 - 2;
            break;
        }
        opt = &(*opt)->next;
    }
    return NO_ERR;
}

packet_error handle_icmp6(struct protocol_info *pinfo, unsigned char *buf, int n,
                          struct packet_data *pdata)
{
    if (n < ICMP6_HDR_LEN)
        return DECODE_ERR;

    struct icmp6_info *icmp6;

    icmp6 = mempool_alloc(sizeof(*icmp6));
    icmp6->option = NULL;
    pdata->data = icmp6;
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    icmp6->type = buf[0];
    icmp6->code = buf[1];
    icmp6->checksum = get_uint16be(buf + 2);
    switch (icmp6->type) {
    case ICMP6_PACKET_TOO_BIG:
        icmp6->checksum = get_uint32be(buf + 4);
        goto parse_ip6;
    case ICMP6_PARAM_PROB:
        icmp6->pointer = get_uint32be(buf + 4);
        FALLTHROUGH;
    case ICMP6_DST_UNREACH:
    case ICMP6_TIME_EXCEEDED:
    parse_ip6:
        if (n > ICMP6_HDR_LEN)
            return parse_data(pdata, buf + ICMP6_HDR_LEN, n - ICMP6_HDR_LEN);
        break;
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        icmp6->echo.id = get_uint16be(buf + 4);
        icmp6->echo.seq = get_uint16be(buf + 6);
        buf += ICMP6_HDR_LEN;
        n -= ICMP6_HDR_LEN;
        if (n > 0)
            icmp6->echo.data = mempool_copy(buf, n);
        icmp6->echo.len = n;
        break;
    case ND_ROUTER_SOLICIT:
        return parse_options(icmp6, pdata, buf + ICMP6_HDR_LEN, n - ICMP6_HDR_LEN);
    case ND_ROUTER_ADVERT:
        buf += ICMP6_HDR_LEN;
        n -= ICMP6_HDR_LEN;
        if (n < 12)
            return DECODE_ERR;
        icmp6->router_adv.cur_hop_limit = buf[0];
        icmp6->router_adv.m = (buf[1] & 0x80) >> 7;
        icmp6->router_adv.o = (buf[1] & 0x40) >> 6;
        buf += 2;
        icmp6->router_adv.router_lifetime = read_uint16be(&buf);
        icmp6->router_adv.reachable_time = read_uint32be(&buf);
        icmp6->router_adv.retrans_timer = read_uint32be(&buf);
        if (n > 0)
            return parse_options(icmp6, pdata, buf, n);
        break;
    case ND_NEIGHBOR_SOLICIT:
        buf += ICMP6_HDR_LEN;
        n -= ICMP6_HDR_LEN;
        if (n < 16)
            return DECODE_ERR;
        PARSE_IP6ADDR(icmp6->target_addr, buf, n);
        if (n > 0)
            return parse_options(icmp6, pdata, buf, n);
        break;
    case ND_NEIGHBOR_ADVERT:
        buf += ICMP6_HDR_LEN;
        n -= ICMP6_HDR_LEN;
        if (n < 5)
            return DECODE_ERR;
        icmp6->neigh_adv.r = (buf[0] & 0x80) >> 7;
        icmp6->neigh_adv.s = (buf[0] & 0x40) >> 6;
        icmp6->neigh_adv.o = (buf[0] & 0x40) >> 5;
        buf += 4; /* skip flags and reserved bytes */
        n -= parse_linkaddr(&icmp6->neigh_adv.target_addr, n, &buf);
        if (n > 0)
            return parse_options(icmp6, pdata, buf, n);
        break;
    case ND_REDIRECT:
        buf += ICMP6_HDR_LEN + 4;
        n -= ICMP6_HDR_LEN;
        if (n < 32)
            return DECODE_ERR;
        PARSE_IP6ADDR(icmp6->redirect.target_addr, buf, n);
        PARSE_IP6ADDR(icmp6->redirect.dest_addr, buf, n);
        if (n > 0)
            return parse_options(icmp6, pdata, buf, n);
        break;
    default:
        break;
    }
    return NO_ERR;
}

char *get_icmp6_type(uint8_t type)
{
    switch (type) {
    case ICMP6_DST_UNREACH:
        return "Destination Unreachable Message";
    case ICMP6_PACKET_TOO_BIG:
        return "Packet Too Big Message";
    case ICMP6_PARAM_PROB:
        return "Parameter Problem Message";
    case ICMP6_ECHO_REQUEST:
        return "Echo Request Message";
    case ICMP6_ECHO_REPLY:
        return "Echo Reply Message";
    case ND_ROUTER_SOLICIT:
        return "Router Solicitation Message";
    case ND_ROUTER_ADVERT:
        return "Router Advertisement Message";
    case ND_NEIGHBOR_SOLICIT:
        return "Neighbor Solicitation Message";
    case ND_NEIGHBOR_ADVERT:
        return "Neighbor Advertisement Message";
    case ND_REDIRECT:
        return "Redirect Message";
    default:
        return NULL;
    }
}

char *get_icmp6_dest_unreach(uint8_t code)
{
    switch (code) {
    case ICMP6_DST_UNREACH_NOROUTE:
        return "No route to destination";
    case ICMP6_DST_UNREACH_ADMIN:
        return "Communication with destination administratively prohibited";
    case ICMP6_DST_UNREACH_BEYONDSCOPE:
        return "Beyond scope of source address";
    case ICMP6_DST_UNREACH_ADDR:
        return "Address unreachable";
    case ICMP6_DST_UNREACH_NOPORT:
        return "Port unreachable";
    case ICMP6_DST_UNREACH_FAILED_POLICY:
        return "Source address failed ingress/egress policy";
    case ICMP6_DST_UNREACH_REJECT_ROUTE:
        return "Reject route to destination";
    default:
        return NULL;
    }
}

char *get_icmp6_time_exceeded(uint8_t code)
{
    switch (code) {
    case ICMP6_TIME_EXCEED_TRANSIT:
        return "Hop limit exceeded in transit";
    case ICMP6_TIME_EXCEED_REASSEMBLY:
        return "Fragment reassembly time exceeded";
    default:
        return NULL;
    }
}

char *get_icmp6_parameter_problem(uint8_t code)
{
    switch (code) {
    case ICMP6_PARAMPROB_HEADER:
        return "Erroneous header field encountered";
    case ICMP6_PARAMPROB_NEXTHEADER:
        return "Unrecognized Next Header type encountered";
    case ICMP6_PARAMPROB_OPTION:
        return "Unrecognized IPv6 option encountered";
    default:
        return NULL;
    }
}

struct packet_flags *get_icmp6_prefix_flags(void)
{
    return prefix_info;
}

int get_icmp6_prefix_flags_size(void)
{
    return ARRAY_SIZE(prefix_info);
}

struct packet_flags *get_icmp6_router_adv_flags(void)
{
    return router_adv_flags;
}

int get_icmp6_router_adv_flags_size(void)
{
    return ARRAY_SIZE(router_adv_flags);
}

struct packet_flags *get_icmp6_neigh_adv_flags(void)
{
    return neigh_adv_flags;
}

int get_icmp6_neigh_adv_flags_size(void)
{
    return ARRAY_SIZE(neigh_adv_flags);
}
