#include "packet_vrrp.h"
#include "packet.h"
#include "packet_ip.h"
#include "packet_ip6.h"
#include "util.h"

#define IPPROTO_VRRP 112
#define VRRP_ADVERTISEMENT 1
#define MIN_VRRP_LEN 8 /* the minimum vrrp packet (without ip addresses) */

static packet_error handle_vrrp(struct protocol_info *pinfo, unsigned char *buf, int n,
                                struct packet_data *pdata);
extern void add_vrrp_information(void *w, void *sw, void *data);
extern void print_vrrp(char *buf, int n, void *data);

static struct protocol_info vrrp_prot = {
    .short_name = "VRRP",
    .long_name = "Virtual Router Redundancy Prototcol",
    .decode = handle_vrrp,
    .print_pdu = print_vrrp,
};

void register_vrrp(void)
{
    register_protocol(&vrrp_prot, IP4_PROT, IPPROTO_VRRP);
    register_protocol(&vrrp_prot, IP6_PROT, IPPROTO_VRRP);
}

static packet_error handle_vrrp(struct protocol_info *pinfo, unsigned char *buf, int n,
                                struct packet_data *pdata)

{
    struct vrrp_info *vrrp;
    struct packet *p;

    if (n < MIN_VRRP_LEN)
        return UNK_PROTOCOL;

    vrrp = mempool_alloc(sizeof(*vrrp));
    pdata->len = n;
    vrrp->version = buf[0] >> 4;
    vrrp->type = buf[0] & 0x0f;
    vrrp->vrid = buf[1];
    vrrp->priority = buf[2];
    vrrp->count_ip = buf[3];
    if (vrrp->version < 3) {
        vrrp->v.auth_type = buf[4];
        vrrp->v.advr_int = buf[5];
    } else if (vrrp->version == 3) {
        vrrp->v3.rsvd = buf[4] >> 4;
        vrrp->v3.max_advr_int = (buf[4] & 0x0f) | buf[5];
    }
    vrrp->checksum = get_uint16be(buf);
    buf += MIN_VRRP_LEN;
    n -= MIN_VRRP_LEN;
    p = get_current_packet();
    if (get_protocol_key(p->root->next->id) == ETHERTYPE_IP) {
        if (vrrp->count_ip * 4 > n) {
            vrrp->ip4_addrs = NULL;
            pdata->error = create_error_string("IP address count too big");
            return DECODE_ERR;
        }
        vrrp->ip4_addrs = mempool_alloc(vrrp->count_ip * 4);
        n = parse_ipv4_addr(vrrp->ip4_addrs, vrrp->count_ip, &buf, n);
    } else {
        if (vrrp->count_ip * 16 > n) {
            vrrp->ip6_addrs = NULL;
            pdata->error = create_error_string("IPv6 address count too big");
            return DECODE_ERR;
        }
        vrrp->ip6_addrs = mempool_alloc(vrrp->count_ip * 16);
        n = parse_ipv6_addr(vrrp->ip6_addrs, vrrp->count_ip, &buf, n);
    }
    if (n > 0 && vrrp->version < 3) {
        if (n != 8) {
            vrrp->v.auth_str[0] = '\0';
            pdata->error = create_error_string("Authentication string should contain 8 bytes (%d)", n);
            return DECODE_ERR;
        }
        memcpy(vrrp->v.auth_str, buf, 8);
        vrrp->v.auth_str[8] = '\0';
    }
    pinfo->num_packets++;
    pinfo->num_bytes += n;
    return NO_ERR;
}

char *get_vrrp_type(uint8_t type)
{
    if (type == VRRP_ADVERTISEMENT)
        return "Advertisement";
    return NULL;
}

char *get_vrrp_auth(uint8_t auth)
{
    switch (auth) {
    case VRRP_NO_AUTHENTICATION:
        return "No authentication";
    case VRRP_V1_AUTH_STP:
        return "Simple text password";
    case VRRP_V1_IP_AUTH_HDR:
        return "IP authentication header";
    default:
        return NULL;
    }
}

char *get_vrrp_priority(uint8_t priority)
{
    switch (priority) {
    case VRRP_PRIORITY_MASTER_RELEASE:
        return "Master has stopped participating in VRRP";
    case VRRP_PRIORITY_BACKUP_DEFAULT:
        return "Default backup priority";
    case VRRP_PRIORITY_OWN_IP:
        return "IP owner";
    default:
        return "Non-default backup priority";
    }
}
