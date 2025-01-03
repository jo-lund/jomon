#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "packet_pim.h"
#include "packet.h"
#include "packet_ip.h"
#include "jomon.h"
#include "af.h"

#define PIM_HEADER_LEN 4

static bool parse_address(unsigned char **data, int *n, pim_addr *addr, uint8_t family,
                          uint8_t encoding);
static bool parse_src_address(unsigned char **data, int *n, struct pim_source_addr *saddr);
static bool parse_grp_address(unsigned char **data, int *n, struct pim_group_addr *gaddr);
static bool parse_unicast_address(unsigned char **data, int *n,
                                  struct pim_unicast_addr *uaddr);
static packet_error handle_pim(struct protocol_info *pinfo, unsigned char *buffer, int n,
                               struct packet_data *pdata);
extern void add_pim_information(void *w, void *sw, void *data);
extern void print_pim(char *buf, int n, void *data);

static struct protocol_info pim_prot = {
    .short_name = "PIM",
    .long_name = "Protocol Independent Multicast",
    .decode = handle_pim,
    .print_pdu = print_pim,
    .add_pdu = add_pim_information
};

void register_pim(void)
{
    register_protocol(&pim_prot, IP4_PROT, IPPROTO_PIM);
    register_protocol(&pim_prot, IP6_PROT, IPPROTO_PIM);
}

static packet_error parse_join_prune(unsigned char *buffer, int n, struct pim_info *pim,
                                     struct packet_data *pdata)
{
    if (n < 4) {
        pdata->error = create_error_string("Packet length (%d) too short", n);
        return DECODE_ERR;
    }
    pim->jpg = mempool_calloc(1, struct pim_join_prune);
    if (!parse_unicast_address(&buffer, &n, &pim->jpg->neighbour)) {
        return DECODE_ERR;
    }
    buffer++; /* next byte is reserved */
    n--;
    pim->jpg->num_groups = buffer[0];
    if (pim->jpg->num_groups > n) {
        pdata->error = create_error_string("Number of multicast groups (%d) greater than packet length (%d)",
                                           pim->jpg->num_groups, n);
        return DECODE_ERR;
    }
    pim->jpg->holdtime = buffer[1] << 8 | buffer[2];
    pim->jpg->groups = mempool_alloc(pim->jpg->num_groups * sizeof(*pim->jpg->groups));
    memset(pim->jpg->groups, 0, pim->jpg->num_groups * sizeof(*pim->jpg->groups));
    buffer += 3;
    n -= 3;
    for (int i = 0; i < pim->jpg->num_groups; i++) {
        if (!parse_grp_address(&buffer, &n, &pim->jpg->groups[i].gaddr)) {
            pdata->error = create_error_string("Error parsing group address");
            return DECODE_ERR;
        }
        if (n < 4) {
            pdata->error = create_error_string("Packet length (%d) too short", n);
            return DECODE_ERR;
        }
        pim->jpg->groups[i].num_joined_src = buffer[0] << 8 | buffer[1];
        pim->jpg->groups[i].num_pruned_src = buffer[2] << 8 | buffer[3];
        n -= 4;
        if (pim->jpg->groups[i].num_joined_src > n) {
            pdata->error = create_error_string("Number of joined source addresses (%d) greater than packet length (%d)",
                                               pim->jpg->groups[i].num_joined_src, n);
            return DECODE_ERR;
        }
        if (pim->jpg->groups[i].num_pruned_src > n) {
            pdata->error = create_error_string("Number of pruned source addresses (%d) greater than packet length (%d)",
                                               pim->jpg->groups[i].num_joined_src, n);
            return DECODE_ERR;
        }
        if (pim->jpg->groups[i].num_joined_src) {
            pim->jpg->groups[i].joined_src = mempool_alloc(pim->jpg->groups[i].num_joined_src *
                                                    sizeof(struct pim_source_addr));
        }
        if (pim->jpg->groups[i].num_pruned_src) {
            pim->jpg->groups[i].pruned_src = mempool_alloc(pim->jpg->groups[i].num_pruned_src *
                                                    sizeof(struct pim_source_addr));
        }
        buffer += 4;
        for (int j = 0; j < pim->jpg->groups[i].num_joined_src; j++) {
            if (!parse_src_address(&buffer, &n, &pim->jpg->groups[i].joined_src[j])) {
                pdata->error = create_error_string("Error parsing source address");
                return DECODE_ERR;
            }
        }
        for (int j = 0; j < pim->jpg->groups[i].num_pruned_src; j++) {
            if (!parse_src_address(&buffer, &n, &pim->jpg->groups[i].pruned_src[j])) {
                pdata->error = create_error_string("Error parsing source address");
                return DECODE_ERR;
            }
        }
    }
    return NO_ERR;
}

static packet_error parse_register_msg(unsigned char *buffer, int n, struct pim_info *pim,
                                       struct packet_data *pdata)
{
    if (n < 4) {
        pdata->error = create_error_string("Packet length (%d) less than minimum PIM register message (4)", n);
        return DECODE_ERR;
    }
    pim->reg = mempool_alloc(sizeof(struct pim_register));
    pim->reg->border = (buffer[0] & 0x80) >> 7; /* Deprecated. Should be zero */
    pim->reg->null = (buffer[0] & 0x40) >> 6;
    buffer += 4;
    n -= 4;
    if (n > 0) {
        pim->reg->data_len = n;
        pim->reg->data = mempool_alloc(pim->reg->data_len);
        memcpy(pim->reg->data, buffer, pim->reg->data_len);
    } else {
        pim->reg->data = NULL;
        pim->reg->data_len = 0;
    }
    return NO_ERR;
}

static packet_error parse_register_stop(unsigned char *buffer, int n, struct pim_info *pim,
                                        struct packet_data *pdata)
{
    pim->reg_stop = mempool_calloc(1, struct pim_register_stop);
    if (!parse_grp_address(&buffer, &n, &pim->reg_stop->gaddr)) {
        pdata->error = create_error_string("Error parsing group address");
        return DECODE_ERR;
    }
    if (!parse_unicast_address(&buffer, &n, &pim->reg_stop->saddr)) {
        pdata->error = create_error_string("Error parsing unicast address");
        return DECODE_ERR;
    }
    return NO_ERR;
}

static packet_error parse_assert_msg(unsigned char *buffer, int n, struct pim_info *pim,
                                     struct packet_data *pdata)
{
    pim->assert = mempool_calloc(1, struct pim_assert);
    if (!parse_grp_address(&buffer, &n, &pim->assert->gaddr)) {
        pdata->error = create_error_string("Error parsing group address");
        return DECODE_ERR;
    }
    if (!parse_unicast_address(&buffer, &n, &pim->assert->saddr)) {
        pdata->error = create_error_string("Error parsing unicast address");
        return DECODE_ERR;
    }
    if (n < 8) {
        pdata->error = create_error_string("Packet length (%d) too short", n);
        return DECODE_ERR;
    }
    pim->assert->metric_pref = get_uint32be(buffer);
    pim->assert->metric = get_uint32be(buffer + 4);
    return NO_ERR;
}

static packet_error parse_bootstrap(unsigned char *buffer, int n, struct pim_info *pim,
                                    struct packet_data *pdata)
{
    if (n < 4) {
        pdata->error = create_error_string("Packet length (%d) too short", n);
        return DECODE_ERR;
    }
    pim->bootstrap = mempool_calloc(1, struct pim_bootstrap);
    pim->bootstrap->tag = buffer[0] << 8 | buffer[1];
    pim->bootstrap->hash_len = buffer[2];
    pim->bootstrap->priority = buffer[3];
    buffer += 4;
    n -= 4;
    if (!parse_unicast_address(&buffer, &n, &pim->bootstrap->bsr_addr)) {
        pdata->error = create_error_string("Error parsing unicast address");
        return DECODE_ERR;
    }

    /*
     * Seems to be no way to know the number of group addresses without actually
     * calculating it based on the message length and the number of RPs in each
     * group. For now we only support 1 group
     */
    pim->bootstrap->groups = mempool_alloc(sizeof(*pim->bootstrap->groups));
    memset(pim->bootstrap->groups, 0, sizeof(*pim->bootstrap->groups));
    if (!parse_grp_address(&buffer, &n, &pim->bootstrap->groups->gaddr)) {
        pdata->error = create_error_string("Error parsing group address");
        return DECODE_ERR;
    }
    if (n < 2) {
        pdata->error = create_error_string("Packet length (%d) too short", n);
        return DECODE_ERR;
    }
    pim->bootstrap->groups->rp_count = buffer[0];
    pim->bootstrap->groups->frag_rp_count = buffer[1];
    n -= 4; /* 2 bytes after frag RP Cnt are reserved */
    if (pim->bootstrap->groups->frag_rp_count > n) {
        pdata->error = create_error_string("Number of Candidate-RP addresses (%d) greater than packet length (%d)",
                                           pim->bootstrap->groups->frag_rp_count, n);
        return DECODE_ERR;
    }
    buffer += 4;
    pim->bootstrap->groups->rps =
        mempool_alloc(pim->bootstrap->groups->frag_rp_count * sizeof(*pim->bootstrap->groups->rps));
    memset(pim->bootstrap->groups->rps, 0, pim->bootstrap->groups->frag_rp_count *
           sizeof(*pim->bootstrap->groups->rps));
    for (int i = 0; i < pim->bootstrap->groups->frag_rp_count; i++) {
        if (!parse_unicast_address(&buffer, &n, &pim->bootstrap->groups->rps->rp_addr)) {
            pdata->error = create_error_string("Error parsing unicast address");
            return DECODE_ERR;
        }
        if (n < 3) {
            pdata->error = create_error_string("Packet length (%d) too short", n);
            return DECODE_ERR;
        }
        pim->bootstrap->groups->rps->holdtime = buffer[0] << 8 | buffer[1];
        pim->bootstrap->groups->rps->priority = buffer[2];
        buffer += 3;
        n -= 3;
    }
    return NO_ERR;
}

static packet_error parse_candidate_rp(unsigned char *buffer, int n, struct pim_info *pim,
                                       struct packet_data *pdata)
{
    pim->candidate = mempool_calloc(1, struct pim_candidate_rp_advertisement);
    pim->candidate->prefix_count = buffer[0];
    if (n < 4 || pim->candidate->prefix_count > n - 4) {
        pdata->error = create_error_string("Packet length (%d) too short", n);
        return DECODE_ERR;
    }
    pim->candidate->priority = buffer[1];
    pim->candidate->holdtime = buffer[2] << 8 | buffer[3];
    buffer += 4;
    n -= 4;
    if (!parse_unicast_address(&buffer, &n, &pim->candidate->rp_addr)) {
        pdata->error = create_error_string("Error parsing unicast address");
        return DECODE_ERR;
    }
    pim->candidate->gaddrs = mempool_calloc(pim->candidate->prefix_count,
                                            struct pim_group_addr);
    for (int i = 0; i < pim->candidate->prefix_count; i++) {
        if (!parse_grp_address(&buffer, &n, &pim->candidate->gaddrs[i])) {
            pdata->error = create_error_string("Error parsing group address");
            return DECODE_ERR;
        }
    }
    return NO_ERR;
}

static packet_error parse_pim_message(unsigned char *buffer, int n, struct pim_info *pim,
                                      struct packet_data *pdata)
{
    switch (pim->type) {
    case PIM_HELLO:
        pim->hello = mempool_alloc(n);
        pim->len = n;
        memcpy(pim->hello, buffer, n);
        return NO_ERR;
    case PIM_REGISTER:
        return parse_register_msg(buffer, n, pim, pdata);
    case PIM_REGISTER_STOP:
        return parse_register_stop(buffer, n, pim, pdata);
    case PIM_BOOTSTRAP:
        return parse_bootstrap(buffer, n, pim, pdata);
    case PIM_ASSERT:
        return parse_assert_msg(buffer, n, pim, pdata);
    case PIM_JOIN_PRUNE:
    case PIM_GRAFT:
    case PIM_GRAFT_ACK:
        return parse_join_prune(buffer, n, pim, pdata);
    case PIM_CANDIDATE_RP_ADVERTISEMENT:
        return parse_candidate_rp(buffer, n, pim, pdata);
    case PIM_STATE_REFRESH:
    default:
        return NO_ERR;
    }
}

/*
 *
 * The PIM header common to all PIM messages:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |PIM Ver| Type  |   Reserved    |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
packet_error handle_pim(struct protocol_info *pinfo, unsigned char *buffer, int n,
                        struct packet_data *pdata)
{
    if (n < PIM_HEADER_LEN)
        return UNK_PROTOCOL;

    struct pim_info *pim;

    pim = mempool_calloc(1, struct pim_info);
    pdata->data = pim;
    pdata->len = n;
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    pim->version = (buffer[0] >> 4) & 0xf;
    pim->type = buffer[0] & 0xf;
    pim->checksum = buffer[1] << 8 | buffer[2];
    return parse_pim_message(buffer + PIM_HEADER_LEN, n - PIM_HEADER_LEN, pim, pdata);
}

bool parse_src_address(unsigned char **data, int *n, struct pim_source_addr *saddr)
{
    unsigned char *ptr = *data;

    if (*n < 4) return false;
    saddr->addr_family = ptr[0];
    saddr->encoding = ptr[1];
    saddr->sparse = (ptr[2] & 0x4) >> 2;
    saddr->wc = (ptr[2] & 0x2) >> 1;
    saddr->rpt = ptr[2] & 0x1;
    saddr->mask_len = ptr[3];
    ptr += 4;
    *n -= 4;
    if (!parse_address(&ptr, n, &saddr->addr, saddr->addr_family, saddr->encoding)) {
        return false;
    }
    *data = ptr;
    return true;
}

bool parse_grp_address(unsigned char **data, int *n, struct pim_group_addr *gaddr)
{
    unsigned char *ptr = *data;

    if (*n < 4)
        return false;
    gaddr->addr_family = ptr[0];
    gaddr->encoding = ptr[1];
    gaddr->bidirectional = (ptr[2] & 0xc0) >> 7;
    gaddr->zone = ptr[2] & 0x01;
    gaddr->mask_len = ptr[3];
    ptr += 4;
    *n -= 4;
    if (!parse_address(&ptr, n, &gaddr->addr, gaddr->addr_family, gaddr->encoding))
        return false;
    *data = ptr;
    return true;
}

bool parse_unicast_address(unsigned char **data, int *n, struct pim_unicast_addr *uaddr)
{
    unsigned char *ptr = *data;

    if (*n < 2)
        return false;
    uaddr->addr_family = ptr[0];
    uaddr->encoding = ptr[1];
    ptr += 2;
    *n -= 2;
    if (!parse_address(&ptr, n, &uaddr->addr, uaddr->addr_family, uaddr->encoding))
        return false;
    *data = ptr;
    return true;
}

bool parse_address(unsigned char **data, int *n, pim_addr *addr, uint8_t family,
                   uint8_t encoding UNUSED)
{
    unsigned char *ptr = *data;

    switch (family) {
    case AFN_IP:
        if (*n < 4)
            return false;
        addr->ipv4_addr = get_uint32le(ptr); /* store in big-endian format */
        ptr += 4;
        *n -= 4;
        break;
    case AFN_IP6:
        if (*n < 16)
            return false;
        memcpy(addr->ipv6_addr, ptr, 16);
        ptr += 16;
        *n -= 16;
        break;
    default:
        DEBUG("PIM: Unknown address family: %d", family);
        return false;
    }
    *data = ptr;
    return true;
}

list_t *parse_hello_options(struct pim_info *pim)
{
    unsigned char *ptr = pim->hello;
    int len = pim->len;
    struct pim_hello *opt;
    list_t *hello_list; /* list of struct pim_hello */

    hello_list = list_init(NULL);
    while (len >= 4) {
        opt = xmalloc(sizeof(struct pim_hello));
        opt->option_type = ptr[0] << 8 | ptr[1];
        opt->option_len = ptr[2] << 8 | ptr[3]; /* length of option value */
        ptr += 4;
        len -= 4;
        switch (opt->option_type) {
        case PIM_HOLDTIME:
            if (len < 2 || opt->option_len != 2)
                goto error;
            opt->holdtime = ptr[0] << 8 | ptr[1];
            break;
        case PIM_LAN_PRUNE_DELAY:
            if (len < 4 || opt->option_len != 4)
                goto error;
            opt->lan_prune_delay.prop_delay = ptr[0] << 8 | ptr[1];
            opt->lan_prune_delay.override_interval = ptr[2] << 8 | ptr[3];
            break;
        case PIM_DR_PRIORITY:
            if (len < 4 || opt->option_len != 4)
                goto error;
            opt->dr_priority = get_uint32be(ptr);
            break;
        case PIM_GENERATION_ID:
            if (len < 4 || opt->option_len != 4)
                goto error;
            opt->gen_id = get_uint32be(ptr);
            break;
        case PIM_STATE_REFRESH_CAPABLE:
            if (len < 4 || opt->option_len != 4) /* 2 bytes are reserved */
                goto error;
            opt->state_refresh.version = ptr[0];
            opt->state_refresh.interval = ptr[1];
            break;
        case PIM_ADDRESS_LIST:
        default:
            break;
        }
        list_push_back(hello_list, opt);
        ptr += opt->option_len;
        len -= opt->option_len;
    }
    return hello_list;

error:
    free(opt);
    return hello_list;
}

char *get_pim_message_type(uint8_t type)
{
    switch (type) {
    case PIM_HELLO:
        return "Hello";
    case PIM_REGISTER:
        return "Register";
    case PIM_REGISTER_STOP:
        return "Register-Stop";
    case PIM_JOIN_PRUNE:
        return "Join/Prune";
    case PIM_BOOTSTRAP:
        return "Bootstrap";
    case PIM_ASSERT:
        return "Assert";
    case PIM_GRAFT:
        return "Graft";
    case PIM_GRAFT_ACK:
        return "Graft-Ack";
    case PIM_CANDIDATE_RP_ADVERTISEMENT:
        return "Candidate-RP-Advertisement";
    case PIM_STATE_REFRESH:
        return "State Refresh";
    default:
        return NULL;
    }
}

char *get_pim_address(uint8_t family, pim_addr *addr)
{
    char *ipaddr;

    switch (family) {
    case AFN_IP:
        ipaddr = xmalloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET, addr, ipaddr, INET_ADDRSTRLEN);
        return ipaddr;
    case AFN_IP6:
        ipaddr = xmalloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, addr, ipaddr, INET6_ADDRSTRLEN);
        return ipaddr;
    default:
        return NULL;
    }
}
