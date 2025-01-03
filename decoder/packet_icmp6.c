#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include "packet_icmp6.h"
#include "packet_ip.h"
#include "attributes.h"
#include "util.h"

#define ICMP6_HDR_LEN 4
#define PARSE_IP6ADDR(addr, buf, n) \
    do {                            \
        memcpy(addr, buf, 16);      \
        (buf) += 16;                \
        (n) -= 16;                  \
    } while (0)

static packet_error handle_icmp6(struct protocol_info *pinfo, unsigned char *buf, int n,
                                 struct packet_data *pdata);
extern void add_icmp6_information(void *w, void *sw, void *data);
extern void print_icmp6(char *buf, int n, void *data);

static struct packet_flags router_adv_flags[] = {
    { "Managed address configuration", 1, NULL },
    { "Other configuration", 1, NULL },
    { "Reserved", 6, NULL }
};

static struct packet_flags prefix_info[] = {
    { "On-link", 1, NULL },
    { "Autonomous address-configuration", 1, NULL },
    { "Reserved", 6, NULL }
};

static struct packet_flags neigh_adv_flags[] = {
    { "Router", 1, NULL },
    { "Solicited", 1, NULL },
    { "Override", 1, NULL },
    { "Reserved", 29, NULL }
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
    register_protocol(&icmp6_prot, IP4_PROT, IPPROTO_ICMPV6);
    register_protocol(&icmp6_prot, IP6_PROT, IPPROTO_ICMPV6);
}

static int parse_linkaddr(uint8_t **addr, int len, unsigned char **buf)
{
    *addr = mempool_alloc(len);
    memcpy(*addr, *buf, len);
    *buf += len;
    return len;
}

static packet_error parse_data(struct packet_data *pdata, unsigned char *buf, int n)
{
    struct protocol_info *pinfo;
    uint32_t id;

    id = get_protocol_id(ETHERNET_II, ETHERTYPE_IPV6);
    pinfo = get_protocol(id);
    pdata->next = mempool_calloc(1, struct packet_data);
    pdata->next->id = id;
    return pinfo->decode(pinfo, buf, n, pdata->next);
}

static packet_error parse_options(struct icmp6_info *icmp6, struct packet_data *pdata,
                                  unsigned char *buf, int n)
{
    struct icmp6_option **opt = &icmp6->option;
    uint8_t nbytes;

    while (n > 0) {
        *opt = mempool_alloc(sizeof(*icmp6->option));
        (*opt)->next = NULL;
        if (n < 2)
            goto error;
        (*opt)->type = buf[0];
        (*opt)->length = buf[1];
        if ((*opt)->length == 0)
            goto error;
        nbytes = (*opt)->length * 8 - 2; /* number of bytes excluding type and length */
        buf += 2;
        n -= 2;
        switch ((*opt)->type) {
        case ND_OPT_SOURCE_LINKADDR:
            if (nbytes > n)
                goto error;
            n -= parse_linkaddr(&(*opt)->source_addr, nbytes, &buf);
            break;
        case ND_OPT_TARGET_LINKADDR:
            if (nbytes > n)
                goto error;
            n -= parse_linkaddr(&(*opt)->target_addr, nbytes, &buf);
            break;
        case ND_OPT_PREFIX_INFORMATION:
            if ((*opt)->length != 4 || nbytes > n)
                goto error;
            (*opt)->prefix_info.prefix_length = buf[0];
            (*opt)->prefix_info.l = (buf[1] & 0x80) >> 7;
            (*opt)->prefix_info.a = (buf[1] & 0x40) >> 6;
            buf += 2;
            n -= 2;
            (*opt)->prefix_info.valid_lifetime = read_uint32be(&buf);
            (*opt)->prefix_info.pref_lifetime =  read_uint32be(&buf);
            buf += 4; /* skip reserved bytes */
            n -= 12;
            (*opt)->prefix_info.prefix = mempool_copy(buf, 16);
            buf += 16;
            n -= 16;
            break;
        case ND_OPT_MTU:
            if ((*opt)->length != 1 || nbytes > n)
                goto error;
            buf += 2; /* skip reserved bytes */
            (*opt)->mtu = read_uint32be(&buf);
            n -= 6;
            break;
        case ND_OPT_REDIRECTED_HEADER:
            if (n < 6)
                goto error;
            buf += 6;  /* skip reserved bytes */
            n -= 6;
            return parse_data(pdata, buf, n);
        default:
            buf += nbytes;
            n -= nbytes;
            break;
        }
        opt = &(*opt)->next;
    }
    return NO_ERR;

error:
    mempool_free(*opt);
    *opt = NULL;
    pdata->error = create_error_string("Error parsing ICMP6 option");
    return DECODE_ERR;
}

packet_error handle_icmp6(struct protocol_info *pinfo, unsigned char *buf, int n,
                          struct packet_data *pdata)
{
    if (n < ICMP6_HDR_LEN)
        return UNK_PROTOCOL;

    struct icmp6_info *icmp6;

    icmp6 = mempool_calloc(1, struct icmp6_info);
    icmp6->option = NULL;
    pdata->data = icmp6;
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    icmp6->type = buf[0];
    icmp6->code = buf[1];
    icmp6->checksum = get_uint16be(buf + 2);
    buf += ICMP6_HDR_LEN;
    n -= ICMP6_HDR_LEN;
    if (n < 4) {
        pdata->error = create_error_string("Packet length (%d) less than minimum ICMP message (4)", n);
        return DECODE_ERR;
    }
    switch (icmp6->type) {
    case ICMP6_DST_UNREACH:
    case ICMP6_TIME_EXCEEDED:
        buf += 4; /* skip unused bytes */
        n -= 4;
        if (n > 0)
            return parse_data(pdata, buf, n);
        break;
    case ICMP6_PACKET_TOO_BIG:
        icmp6->checksum = read_uint32be(&buf);
        n -= 4;
        if (n > 0)
            return parse_data(pdata, buf, n);
        break;
    case ICMP6_PARAM_PROB:
        icmp6->pointer = read_uint32be(&buf);
        n -= 4;
        if (n > 0)
            return parse_data(pdata, buf, n);
        break;
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        icmp6->echo.id = read_uint16be(&buf);
        icmp6->echo.seq = read_uint16be(&buf);
        n -= 4;
        if (n > 0)
            icmp6->echo.data = buf;
        icmp6->echo.len = n;
        break;
    case ND_ROUTER_SOLICIT:
        buf += 4; /* skip reserved bytes */
        n -= 4;
        return parse_options(icmp6, pdata, buf, n);
    case ND_ROUTER_ADVERT:
        if (n < 12) {
            pdata->error =
                create_error_string("Packet length (%d) less than router advertisement message length (12)", n);
            return DECODE_ERR;
        }
        icmp6->router_adv.cur_hop_limit = buf[0];
        icmp6->router_adv.m = (buf[1] & 0x80) >> 7;
        icmp6->router_adv.o = (buf[1] & 0x40) >> 6;
        buf += 2;
        icmp6->router_adv.router_lifetime = read_uint16be(&buf);
        icmp6->router_adv.reachable_time = read_uint32be(&buf);
        icmp6->router_adv.retrans_timer = read_uint32be(&buf);
        n -= 12;
        if (n > 0)
            return parse_options(icmp6, pdata, buf, n);
        break;
    case ND_NEIGHBOR_SOLICIT:
        if (n < 20) {
            pdata->error =
                create_error_string("Packet length (%d) less than neighbor solicitation  message length (20)", n);
            return DECODE_ERR;
        }
        buf += 4; /* skip reserved bytes */
        n -= 4;
        PARSE_IP6ADDR(icmp6->target_addr, buf, n);
        if (n > 0)
            return parse_options(icmp6, pdata, buf, n);
        break;
    case ND_NEIGHBOR_ADVERT:
        if (n < 20) {
            pdata->error =
                create_error_string("Packet length (%d) less than neighbor advertisement message length (20)", n);
            return DECODE_ERR;
        }
        icmp6->neigh_adv.r = (buf[0] & 0x80) >> 7;
        icmp6->neigh_adv.s = (buf[0] & 0x40) >> 6;
        icmp6->neigh_adv.o = (buf[0] & 0x20) >> 5;
        buf += 4; /* skip flags and reserved bytes */
        n -= 4;
        PARSE_IP6ADDR(icmp6->neigh_adv.target_addr, buf, n);
        if (n > 0)
            return parse_options(icmp6, pdata, buf, n);
        break;
    case ND_REDIRECT:
        if (n < 36) {
            pdata->error =
                create_error_string("Packet length (%d) less than redirect message length (36)", n);
            return DECODE_ERR;
        }
        buf += 4; /* skip reserved bytes */
        n -= 4;
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
        return "Unknown type";
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
        return "Unknown code";
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
        return "Unknown code";
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
        return "Unknown code";
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
