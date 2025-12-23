#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "packet_icmp6.h"
#include "packet.h"
#include "attributes.h"
#include "util.h"
#include "field.h"
#include "string.h"

#define ICMP6_HDR_LEN 4

static char *get_icmp6_type(uint8_t type);
static char *get_icmp6_dest_unreach(uint8_t code);
static char *get_icmp6_time_exceeded(uint8_t code);
static char *get_icmp6_parameter_problem(uint8_t code);
static packet_error handle_icmp6(struct protocol_info *pinfo, unsigned char *buf, int n,
                                 struct packet_data *pdata);
static void print_icmp6(char *buf, int n, struct packet_data *pdata);

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
};

void register_icmp6(void)
{
    register_protocol(&icmp6_prot, IP4_PROT, IPPROTO_ICMPV6);
    register_protocol(&icmp6_prot, IP6_PROT, IPPROTO_ICMPV6);
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

static packet_error parse_options(struct packet_data *pdata, unsigned char *buf, int n)

{
    uint8_t nbytes, type, length;

    while (n > 0) {
        if (n < 2)
            goto error;
        type = buf[0];
        length = buf[1];
        if (length == 0)
            goto error;
        nbytes = length * 8 - 2; /* number of bytes excluding type and length */
        buf += 2;
        n -= 2;
        switch (type) {
        case ND_OPT_SOURCE_LINKADDR:
            if (nbytes > n && n < 6)
                goto error;
            field_add_value(pdata->data, "Source link-layer address", FIELD_STRING_HEADER, NULL);
            field_add_value(pdata->data, "Type", FIELD_UINT8, UINT_TO_PTR(type));
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            field_add_bytes(pdata->data, "Link-layer address",
                            nbytes == 6 ? FIELD_HWADDR : FIELD_BYTES, buf, nbytes);
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            buf += nbytes;
            n -= nbytes;
            break;
        case ND_OPT_TARGET_LINKADDR:
            if (nbytes > n && n < 6)
                goto error;
            field_add_value(pdata->data, "Target link-layer address", FIELD_STRING_HEADER, NULL);
            field_add_value(pdata->data, "Type", FIELD_UINT8, UINT_TO_PTR(type));
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            field_add_bytes(pdata->data, "Link-layer address",
                            nbytes == 6 ? FIELD_HWADDR : FIELD_BYTES, buf, nbytes);
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            buf += nbytes;
            n -= nbytes;
            break;
        case ND_OPT_PREFIX_INFORMATION:
            if (length != 4 || nbytes > n || n < 30)
                goto error;
            field_add_value(pdata->data, "Prefix information", FIELD_STRING_HEADER, NULL);
            field_add_value(pdata->data, "Type", FIELD_UINT8, UINT_TO_PTR(type));
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            field_add_value(pdata->data, "Prefix length", FIELD_UINT8, UINT_TO_PTR(buf[0]));
            field_add_bitfield(pdata->data, "Flags", buf[1], false, prefix_info, ARRAY_SIZE(prefix_info));
            buf += 2;
            n -= 2;
            field_add_value(pdata->data, "Valid lifetime", FIELD_TIMESTAMP_SEC,
                            UINT_TO_PTR(read_uint32be(&buf)));
            field_add_value(pdata->data, "Preferred lifetime", FIELD_TIMESTAMP_SEC,
                            UINT_TO_PTR(read_uint32be(&buf)));
            buf += 4; /* skip reserved bytes */
            n -= 12;
            field_add_bytes(pdata->data, "Prefix", FIELD_IP6ADDR, buf, 16);
            buf += 16;
            n -= 16;
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            break;
        case ND_OPT_MTU:
        {
            uint32_t mtu;

            if (length != 1 || nbytes > n || n < 6)
                goto error;
            buf += 2; /* skip reserved bytes */
            mtu = read_uint32be(&buf);
            n -= 6;
            field_add_value(pdata->data, "MTU", FIELD_STRING_HEADER_INT, UINT_TO_PTR(mtu));
            field_add_value(pdata->data, "Type", FIELD_UINT8, UINT_TO_PTR(type));
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            field_add_value(pdata->data, "Recommended MTU for the link", FIELD_UINT32, UINT_TO_PTR(mtu));
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            break;
        }
        case ND_OPT_REDIRECTED_HEADER:
            if (n < 6)
                goto error;
            field_add_value(pdata->data, "Redirect header", FIELD_STRING_HEADER, NULL);
            field_add_value(pdata->data, "Type", FIELD_UINT8, UINT_TO_PTR(type));
            field_add_value(pdata->data, "Length", FIELD_UINT8, UINT_TO_PTR(length));
            field_add_value(pdata->data, "", FIELD_STRING_HEADER_END, NULL);
            buf += 6;  /* skip reserved bytes */
            n -= 6;
            return parse_data(pdata, buf, n);
        default:
            buf += nbytes;
            n -= nbytes;
            break;
        }
    }
    field_finish(pdata->data);
    return NO_ERR;

error:
    pdata->error = create_error_string("Error parsing ICMP6 option");
    field_finish(pdata->data);
    return DECODE_ERR;
}

packet_error handle_icmp6(struct protocol_info *pinfo, unsigned char *buf, int n,
                          struct packet_data *pdata)
{
    if (n < ICMP6_HDR_LEN)
        return UNK_PROTOCOL;

    struct uint_string type, code;

    pdata->data = field_init();
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    type.val = buf[0];
    type.str = get_icmp6_type(buf[0]);
    buf++;
    field_add_value(pdata->data, "Type", FIELD_UINT_STRING, &type);
    if (n - ICMP6_HDR_LEN < 4) {
        pdata->error = create_error_string("Packet length (%d) less than minimum ICMP message (4)", n);
        field_finish(pdata->data);
        return DECODE_ERR;
    }
    n--;
    switch (type.val) {
    case ICMP6_DST_UNREACH:
        code.val = buf[0];
        code.str = get_icmp6_dest_unreach(buf[0]);
        buf++;
        n--;
        field_add_value(pdata->data, "Code", FIELD_UINT_STRING, &code);
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        n -= 2;
        buf += 4; /* skip unused bytes */
        n -= 4;
        if (n > 0)
            return parse_data(pdata, buf, n);
        break;
    case ICMP6_TIME_EXCEEDED:
        code.val = buf[0];
        code.str = get_icmp6_time_exceeded(buf[0]);
        buf++;
        n--;
        field_add_value(pdata->data, "Code", FIELD_UINT_STRING, &code);
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        buf += 4; /* skip unused bytes */
        n -= 6;
        if (n > 0)
            return parse_data(pdata, buf, n);
        break;
    case ICMP6_PACKET_TOO_BIG:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        n--;
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "MTU", FIELD_UINT32, UINT_TO_PTR(read_uint32be(&buf)));
        n -= 6;
        if (n > 0)
            return parse_data(pdata, buf, n);
        break;
    case ICMP6_PARAM_PROB:
        code.val = buf[0];
        code.str = get_icmp6_parameter_problem(buf[0]);
        buf++;
        n--;
        field_add_value(pdata->data, "Code", FIELD_UINT_STRING, &code);
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Pointer", FIELD_UINT32, UINT_TO_PTR(read_uint32be(&buf)));
        n -= 6;
        if (n > 0)
            return parse_data(pdata, buf, n);
        break;
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Identifier", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Sequence number", FIELD_UINT16, UINT_TO_PTR(read_uint16be(&buf)));
        n -= 7;
        if (n > 0)
            field_add_bytes(pdata->data, "Data", FIELD_BYTES, buf, n);
        break;
    case ND_ROUTER_SOLICIT:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        buf += 4; /* skip reserved bytes */
        n -= 7;
        return parse_options(pdata, buf, n);
    case ND_ROUTER_ADVERT:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        n -= 3;
        if (n < 12) {
            pdata->error =
                create_error_string("Packet length (%d) less than router advertisement message length (12)", n);
            field_finish(pdata->data);
            return DECODE_ERR;
        }
        field_add_value(pdata->data, "Cur hop limit", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_bitfield(pdata->data, "Flags", buf[0], false, router_adv_flags, ARRAY_SIZE(router_adv_flags));
        buf++;
        field_add_value(pdata->data, "Router lifetime", FIELD_TIMESTAMP_SEC, UINT_TO_PTR(read_uint16be(&buf)));
        field_add_value(pdata->data, "Reachable time", FIELD_TIMESTAMP, UINT_TO_PTR(read_uint32be(&buf)));
        field_add_value(pdata->data, "Retrans timer", FIELD_TIMESTAMP, UINT_TO_PTR(read_uint32be(&buf)));
        n -= 12;
        if (n > 0)
            return parse_options(pdata, buf, n);
        break;
    case ND_NEIGHBOR_SOLICIT:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        n -= 3;
        if (n < 20) {
            pdata->error =
                create_error_string("Packet length (%d) less than neighbor solicitation  message length (20)", n);
            field_finish(pdata->data);
            return DECODE_ERR;
        }
        buf += 4; /* skip reserved bytes */
        n -= 4;
        field_add_bytes(pdata->data, "Target address", FIELD_IP6ADDR, buf, 16);
        buf += 16;
        n -= 16;
        if (n > 0)
            return parse_options(pdata, buf, n);
        break;
    case ND_NEIGHBOR_ADVERT:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        n -= 3;
        if (n < 20) {
            pdata->error =
                create_error_string("Packet length (%d) less than neighbor advertisement message length (20)", n);
            field_finish(pdata->data);
            return DECODE_ERR;
        }
        field_add_bitfield(pdata->data, "Flags", buf[0], false, neigh_adv_flags, ARRAY_SIZE(neigh_adv_flags));
        buf += 4; /* skip flags and reserved bytes */
        n -= 4;
        field_add_bytes(pdata->data, "Target address", FIELD_IP6ADDR, buf, 16);
        buf += 16;
        n -= 16;
        if (n > 0)
            return parse_options(pdata, buf, n);
        break;
    case ND_REDIRECT:
        field_add_value(pdata->data, "Code", FIELD_UINT8, UINT_TO_PTR(*buf++));
        field_add_value(pdata->data, "Checksum", FIELD_UINT16_HEX, UINT_TO_PTR(read_uint16be(&buf)));
        n -= 3;
        if (n < 36) {
            pdata->error =
                create_error_string("Packet length (%d) less than redirect message length (36)", n);
            field_finish(pdata->data);
            return DECODE_ERR;
        }
        buf += 4; /* skip reserved bytes */
        n -= 4;
        field_add_bytes(pdata->data, "Target address", FIELD_IP6ADDR, buf, 16);
        buf += 16;
        n -= 16;
        field_add_bytes(pdata->data, "Destination address", FIELD_IP6ADDR, buf, 16);
        buf += 16;
        n -= 16;
        if (n > 0)
            return parse_options(pdata, buf, n);
        break;
    default:
        break;
    }
    field_finish(pdata->data);
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

static void print_icmp6(char *buf, int n, struct packet_data *pdata)
{
    struct uint_string *type, *code;
    const struct field *f;

    type = field_search_value(pdata->data, "Type");
    switch (type->val) {
    case ICMP6_DST_UNREACH:
        code = field_search_value(pdata->data, "Code");
        snprintf(buf, n, "%s", code->str);
        break;
    case ICMP6_PACKET_TOO_BIG:
        snprintf(buf, n, "Packet too big message: MTU = %d",
                 (uint32_t) PTR_TO_UINT(field_search_value(pdata->data, "MTU")));
        break;
    case ICMP6_TIME_EXCEEDED:
        code = field_search_value(pdata->data, "Code");
        snprintf(buf, n, "%s", code->str);
        break;
    case ICMP6_PARAM_PROB:
        code = field_search_value(pdata->data, "Code");
        snprintf(buf, n, "%s: Pointer = %d", code->str,
                 (uint32_t) PTR_TO_UINT(field_search_value(pdata->data, "Pointer")));
        break;
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        snprintf(buf, n, "%s: id = 0x%x  seq = %u", type->str,
                 (uint16_t) PTR_TO_UINT(field_search_value(pdata->data, "Identifier")),
                 (uint16_t) PTR_TO_UINT(field_search_value(pdata->data, "Sequence number")));
        break;
    case ND_ROUTER_SOLICIT:
        snprintf(buf, n, "%s", type->str);
        break;
    case ND_ROUTER_ADVERT:
        f = field_search(pdata->data, "Source link-layer address");
        if (f) {
            char link[HW_ADDRSTRLEN];
            unsigned char *addr;

            while (f && strcmp(field_get_key(f), "Link-layer address") != 0)
                   f = field_get_next(f);
            addr = field_get_value(f);
            HW_ADDR_NTOP(link, addr);
            snprintf(buf, n, "Router Advertisement from %s", link);
        } else {
            snprintf(buf, n, "Router Advertisement");
        }
        break;
    case ND_NEIGHBOR_SOLICIT:
    {
        char target[INET6_ADDRSTRLEN];
        unsigned char *addr;

        addr = field_search_value(pdata->data, "Target address");
        inet_ntop(AF_INET6, (struct in_addr *) addr, target, INET6_ADDRSTRLEN);
        snprintf(buf, n, "Neighbor Solicitation for %s", target);
        break;
    }
    case ND_NEIGHBOR_ADVERT:
    {
        char target[INET6_ADDRSTRLEN];
        unsigned char *addr;

        addr = field_search_value(pdata->data, "Target address");
        inet_ntop(AF_INET6, (struct in_addr *) addr, target, INET6_ADDRSTRLEN);
        f = field_search(pdata->data, "Target link-layer address");
        if (f) {
            char link[HW_ADDRSTRLEN];

            while (f && strcmp(field_get_key(f), "Link-layer address") != 0)
                f = field_get_next(f);
            addr = field_get_value(f);
            HW_ADDR_NTOP(link, addr);
            snprintf(buf, n, "Neighbor Advertisement %s is at %s", target, link);
        } else {
            snprintf(buf, n, "Neighbor Advertisement from %s", target);
        }
        break;
    }
    case ND_REDIRECT:
    {
        char target[INET6_ADDRSTRLEN];
        char dest[INET6_ADDRSTRLEN];
        unsigned char *addr;

        addr = field_search_value(pdata->data, "Target address");
        inet_ntop(AF_INET6, (struct in_addr *) addr, target, INET6_ADDRSTRLEN);
        addr = field_search_value(pdata->data, "Destination address");
        inet_ntop(AF_INET6, (struct in_addr *) addr, dest, INET6_ADDRSTRLEN);
        snprintf(buf, n, "Redirect. Target: %s  Destination: %s", target, dest);
        break;
    }
    default:
        snprintf(buf, n, "%s", type->str);
        break;
    }
}
