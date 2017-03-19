#include "packet_pim.h"
#include "packet.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#define PIM_HEADER_LEN 4

static bool parse_pim_message(unsigned char *buffer, int n, struct pim_info *pim);
static bool parse_register_msg(unsigned char *buffer, int n, struct pim_info *pim);
static bool parse_register_stop(unsigned char *buffer, int n, struct pim_info *pim);
static bool parse_assert_msg(unsigned char *buffer, int n, struct pim_info *pim);
static bool parse_join_prune(unsigned char *buffer, int n, struct pim_info *pim);
static unsigned char *parse_address(unsigned char **data, uint8_t family,
                                    uint8_t encoding);
static void parse_src_address(unsigned char **data, struct pim_source_addr *saddr);
static void parse_grp_address(unsigned char **data, struct pim_group_addr *gaddr);
static void parse_unicast_address(unsigned char **data, struct pim_unicast_addr *uaddr);

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
bool handle_pim(unsigned char *buffer, int n, struct pim_info *pim)
{
    if (n < PIM_HEADER_LEN) return false;

    pstat.num_pim++;
    pstat.bytes_pim += n;
    pim->version = (buffer[0] >> 4) & 0xf;
    pim->type = buffer[0] & 0xf;
    pim->checksum = buffer[1] << 8 | buffer[2];
    return parse_pim_message(buffer + PIM_HEADER_LEN, n - PIM_HEADER_LEN, pim);
}

bool parse_pim_message(unsigned char *buffer, int n, struct pim_info *pim)
{
    switch (pim->type) {
    case PIM_HELLO:
        pim->hello = malloc(n);
        pim->len = n;
        memcpy(pim->hello, buffer, n);
        return true;
    case PIM_REGISTER:
        return parse_register_msg(buffer, n, pim);
    case PIM_REGISTER_STOP:
        return parse_register_stop(buffer, n, pim);
    case PIM_BOOTSTRAP:
        return true;
    case PIM_ASSERT:
        return parse_assert_msg(buffer, n, pim);
    case PIM_JOIN_PRUNE:
    case PIM_GRAFT:
    case PIM_GRAFT_ACK:
        return parse_join_prune(buffer, n, pim);
    case PIM_CANDIDATE_RP_ADVERTISEMENT:
    case PIM_STATE_REFRESH:
    default:
        return true;
    }
}

bool parse_join_prune(unsigned char *buffer, int n, struct pim_info *pim)
{
    // TODO: Add a check for minimum packet size
    pim->jpg = malloc(sizeof(struct pim_join_prune));
    parse_unicast_address(&buffer, &pim->jpg->neighbour);
    buffer++; /* next byte is reserved */
    pim->jpg->num_groups = buffer[0];
    pim->jpg->holdtime = buffer[1] << 8 | buffer[2];
    pim->jpg->groups = calloc(pim->jpg->num_groups, sizeof(*pim->jpg->groups));
    buffer += 3;

    for (int i = 0; i < pim->jpg->num_groups; i++) {
        parse_grp_address(&buffer, &pim->jpg->groups[i].gaddr);
        pim->jpg->groups[i].num_joined_src = buffer[0] << 8 | buffer[1];
        pim->jpg->groups[i].num_pruned_src = buffer[2] << 8 | buffer[3];
        if (pim->jpg->groups[i].num_joined_src) {
            pim->jpg->groups[i].joined_src = calloc(pim->jpg->groups[i].num_joined_src,
                                              sizeof(struct pim_source_addr));
        }
        if (pim->jpg->groups[i].num_pruned_src) {
            pim->jpg->groups[i].pruned_src = calloc(pim->jpg->groups[i].num_joined_src,
                                              sizeof(struct pim_source_addr));
        }
        buffer += 4;
        for (int j = 0; j < pim->jpg->groups[i].num_joined_src; j++) {
            parse_src_address(&buffer, &pim->jpg->groups[i].joined_src[j]);
        }
        for (int j = 0; j < pim->jpg->groups[i].num_pruned_src; j++) {
            parse_src_address(&buffer, &pim->jpg->groups[i].pruned_src[j]);
        }
    }

    return true;
}

bool parse_register_msg(unsigned char *buffer, int n, struct pim_info *pim)
{
    // TODO: Add a check for minimum packet size
    pim->reg = malloc(sizeof(struct pim_register));
    pim->reg->border = (buffer[0] & 0x80) >> 7; /* Deprecated. Should be zero */
    pim->reg->null = (buffer[0] & 0x40) >> 6;
    buffer += 4;
    if (n - 4 > 0) {
        pim->reg->data_len = n - 4;
        pim->reg->data = malloc(pim->reg->data_len);
        memcpy(pim->reg->data, buffer, pim->reg->data_len);
    } else {
        pim->reg->data = NULL;
        pim->reg->data_len = 0;
    }
    return true;
}

bool parse_register_stop(unsigned char *buffer, int n, struct pim_info *pim)
{
    // TODO: Add a check for minimum packet size
    pim->reg_stop = malloc(sizeof(struct pim_register_stop));

    parse_grp_address(&buffer, &pim->reg_stop->gaddr);
    parse_unicast_address(&buffer, &pim->reg_stop->saddr);
    return true;
}

bool parse_assert_msg(unsigned char *buffer, int n, struct pim_info *pim)
{
    if (n < 18) return false;

    pim->assert = malloc(sizeof(struct pim_assert));
    parse_grp_address(&buffer, &pim->assert->gaddr);
    parse_unicast_address(&buffer, &pim->assert->saddr);
    pim->assert->metric_pref = buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[0];
    pim->assert->metric= buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[0];

    return true;
}

void parse_src_address(unsigned char **data, struct pim_source_addr *saddr)
{
    unsigned char *ptr = *data;

    saddr->addr_family = ptr[0];
    saddr->encoding = ptr[1];
    saddr->sparse = (ptr[2] & 0x4) >> 2;
    saddr->wc = (ptr[2] & 0x2) >> 1;
    saddr->rpt = ptr[2] & 0x1;
    saddr->mask_len = ptr[3];
    ptr += 4;
    saddr->addr = parse_address(&ptr, saddr->addr_family, saddr->encoding);
    *data = ptr;
}

void parse_grp_address(unsigned char **data, struct pim_group_addr *gaddr)
{
    unsigned char *ptr = *data;

    gaddr->addr_family = ptr[0];
    gaddr->encoding = ptr[1];
    gaddr->bidirectional = (ptr[2] & 0xc0) >> 7;
    gaddr->zone = ptr[2] & 0x01;
    gaddr->mask_len = ptr[3];
    ptr += 4;
    gaddr->addr = parse_address(&ptr, gaddr->addr_family, gaddr->encoding);
    *data = ptr;
}

void parse_unicast_address(unsigned char **data, struct pim_unicast_addr *uaddr)
{
    unsigned char *ptr = *data;

    uaddr->addr_family = ptr[0];
    uaddr->encoding = ptr[1];
    ptr += 2;
    uaddr->addr = parse_address(&ptr, uaddr->addr_family, uaddr->encoding);
    *data = ptr;
}

unsigned char *parse_address(unsigned char **data, uint8_t family, uint8_t encoding)
{
    unsigned char *addr = NULL;
    unsigned char *ptr = *data;

    switch (family) {
    case AF_IP:
        addr = malloc(4);
        memcpy(addr, ptr, 4);
        ptr += 4;
        break;
    case AF_IP6:
        addr = malloc(16);
        memcpy(addr, ptr, 16);
        ptr += 16;
        break;
    default:
        printf("PIM: Unknown address family: %d\n", family);
    }
    *data = ptr;
    return addr;
}

list_t *parse_hello_options(struct pim_info *pim)
{
    unsigned char *ptr = pim->hello;
    int len = pim->len;
    struct pim_hello *opt;
    list_t *hello_list; /* list of struct pim_hello */

    hello_list = list_init();
    while (len >= 4) {
        opt = malloc(sizeof(struct pim_hello));
        opt->option_type = ptr[0] << 8 | ptr[1];
        opt->option_len = ptr[2] << 8 | ptr[3]; /* length of option value */
        ptr += 4;
        len -= 4;
        switch (opt->option_type) {
        case PIM_HOLDTIME:
            opt->holdtime = ptr[0] << 8 | ptr[1];
            break;
        case PIM_LAN_PRUNE_DELAY:
            opt->lan_prune_delay.prop_delay = ptr[0] << 8 | ptr[1];
            opt->lan_prune_delay.override_interval = ptr[2] << 8 | ptr[3];
            break;
        case PIM_DR_PRIORITY:
            opt->dr_priority = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            break;
        case PIM_GENERATION_ID:
            opt->gen_id = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
            break;
        case PIM_STATE_REFRESH_CAPABLE:
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

char *get_pim_address(uint8_t family, unsigned char *addr)
{
    switch (family) {
    case AF_IP:
    {
        char *ipaddr;

        ipaddr = malloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET, addr, ipaddr, INET_ADDRSTRLEN);
        return ipaddr;
    }
    case AF_IP6:
    {
        char *ipaddr;

        ipaddr = malloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, addr, ipaddr, INET6_ADDRSTRLEN);
        return ipaddr;
    }
    default:
        return NULL;
    }
}

void free_pim_packet(struct pim_info *pim)
{
    switch (pim->type) {
    case PIM_HELLO:
        free(pim->hello);
        break;
    case PIM_REGISTER:
        if (pim->reg->data) {
            free(pim->reg->data);
        }
        free(pim->reg);
        break;
    case PIM_REGISTER_STOP:
        if (pim->reg_stop->gaddr.addr) {
            free(pim->reg_stop->gaddr.addr);
        }
        if (pim->reg_stop->saddr.addr) {
            free(pim->reg_stop->saddr.addr);
        }
        free(pim->reg_stop);
        break;
    case PIM_BOOTSTRAP:
        break;
    case PIM_ASSERT:
        if (pim->assert->gaddr.addr) {
            free(pim->assert->gaddr.addr);
        }
        if (pim->assert->saddr.addr) {
            free(pim->assert->saddr.addr);
        }
        free(pim->assert);
        break;
    case PIM_JOIN_PRUNE:
    case PIM_GRAFT:
    case PIM_GRAFT_ACK:
        if (pim->jpg->neighbour.addr) {
            free(pim->jpg->neighbour.addr);
        }
        if (pim->jpg->groups) {
            for (int i = 0; i < pim->jpg->num_groups; i++) {
                if (pim->jpg->groups->gaddr.addr) {
                    free(pim->jpg->groups->gaddr.addr);
                }
                for (int j = 0; j < pim->jpg->groups->num_joined_src; j++) {
                    if (pim->jpg->groups->joined_src[j].addr) {
                        free(pim->jpg->groups->joined_src[j].addr);
                    }
                }
                if (pim->jpg->groups->joined_src) {
                    free(pim->jpg->groups->joined_src);
                }
                for (int j = 0; j < pim->jpg->groups->num_pruned_src; j++) {
                    if (pim->jpg->groups->pruned_src[j].addr) {
                        free(pim->jpg->groups->pruned_src[j].addr);
                    }
                }
                if (pim->jpg->groups->pruned_src) {
                    free(pim->jpg->groups->pruned_src);
                }
            }
            free(pim->jpg->groups);
        }
        free(pim->jpg);
        break;
    case PIM_CANDIDATE_RP_ADVERTISEMENT:
        break;
    default:
        break;
    }
}
