#include "packet_pim.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#define PIM_HEADER_LEN 4

static bool parse_pim_message(unsigned char *buffer, int n, struct pim_info *pim);
static bool parse_register_msg(unsigned char *buffer, int n, struct pim_info *pim);
static bool parse_assert_msg(unsigned char *buffer, int n, struct pim_info *pim);
static bool parse_join_prune(unsigned char *buffer, int n, struct pim_info *pim);
static unsigned char *parse_address(unsigned char **data, uint8_t family,
                                    uint8_t encoding);

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
        return false;
    case PIM_JOIN_PRUNE:
        return parse_join_prune(buffer, n, pim);
    case PIM_BOOTSTRAP:
        return false;
    case PIM_ASSERT:
        return parse_assert_msg(buffer, n, pim);
    case PIM_GRAFT:
    case PIM_GRAFT_ACK:
    case PIM_CANDIDATE_RP_ADVERTISEMENT:
    default:
        return false;
    }
}

bool parse_join_prune(unsigned char *buffer, int n, struct pim_info *pim)
{
    return false;
}

bool parse_register_msg(unsigned char *buffer, int n, struct pim_info *pim)
{
    return false;
}

bool parse_assert_msg(unsigned char *buffer, int n, struct pim_info *pim)
{
    if (n < 18) return false;

    struct pim_group_addr gaddr;
    struct pim_unicast_addr saddr;

    pim->assert = malloc(sizeof(struct pim_assert));
    gaddr.addr_family = buffer[0];
    gaddr.encoding = buffer[1];
    gaddr.bidirectional = (buffer[2] & 0xc0) >> 7;
    gaddr.zone = buffer[2] & 0x01;
    gaddr.mask_len = buffer[3];
    buffer += 4;
    gaddr.addr = parse_address(&buffer, gaddr.addr_family, gaddr.encoding);

    saddr.addr_family = buffer[0];
    saddr.encoding = buffer[1];
    buffer += 2;
    saddr.addr = parse_address(&buffer, saddr.addr_family, saddr.encoding);

    pim->assert->gaddr = gaddr;
    pim->assert->saddr = saddr;
    pim->assert->metric_pref = buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[0];
    pim->assert->metric= buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[0];

    return true;
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

    hello_list = list_init(NULL);
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
        break;
    case PIM_REGISTER_STOP:
        break;
    case PIM_JOIN_PRUNE:
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
    case PIM_GRAFT:
        break;
    case PIM_GRAFT_ACK:
        break;
    case PIM_CANDIDATE_RP_ADVERTISEMENT:
        break;
    default:
        break;
    }
}
