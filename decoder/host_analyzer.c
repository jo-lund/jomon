#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "host_analyzer.h"
#include "packet.h"
#include "packet_ip.h"
#include "../signal.h"
#include "packet_dns.h"
#include "dns_cache.h"

#define TBLSZ 1024

static hash_map_t *local_hosts;
static hash_map_t *remote_hosts;
static publisher_t *host_changed_publisher;

static void handle_ip4(struct packet *p);
static bool local_ip4(uint32_t addr);
static void insert_host(uint32_t ipaddr, uint8_t *mac);

void host_analyzer_init()
{
    local_hosts = hash_map_init(TBLSZ, NULL, NULL);
    remote_hosts = hash_map_init(TBLSZ, NULL, NULL);
    host_changed_publisher = publisher_init();
}

void host_analyzer_free()
{
    hash_map_free(local_hosts);
    hash_map_free(remote_hosts);
    publisher_free(host_changed_publisher);
}

void host_analyzer_investigate(struct packet *p)
{
    if (!local_hosts && !remote_hosts) return;

    switch (p->eth.ethertype) {
    case ETH_P_IP:
        handle_ip4(p);
        break;
    default:
        break;
    }
}

hash_map_t *host_analyzer_get_local()
{
    return local_hosts;
}

hash_map_t *host_analyzer_get_remote()
{
    return remote_hosts;
}

void host_analyzer_subscribe(analyzer_host_fn fn)
{
    add_subscription2(host_changed_publisher, (publisher_fn2) fn);
}

void host_analyzer_unsubscribe(analyzer_host_fn fn)
{
    remove_subscription2(host_changed_publisher, (publisher_fn2) fn);
}

void host_analyzer_clear()
{
    hash_map_clear(local_hosts);
    hash_map_clear(remote_hosts);
}

void handle_ip4(struct packet *p)
{
    // TODO: Filter out broadcast and multicast
    insert_host(p->eth.ip->src, p->eth.mac_src);
    insert_host(p->eth.ip->dst, p->eth.mac_dst);

    // TODO: Inspect packet
    switch (p->eth.ip->protocol) {
    case IPPROTO_TCP:
        break;
    case IPPROTO_UDP:
        break;
    default:
        break;
    }
}

bool local_ip4(uint32_t addr)
{
    /* class A: 10.0.0.0 - 10.255.255.255 */
    if ((addr & 0xff) == 10) return true;

    /* class B: 172.16.0.0 - 172.31.255.255 */
    if ((addr & 0xffff) >= 4268 && (addr & 0xffff) <= 8108) return true;

    /* class C: 192.168.0.0 - 192.168.255.255 */
    if ((addr & 0xffff) == 43200) return true;

    return false;
}

void insert_host(uint32_t ipaddr, uint8_t *mac)
{
    hash_map_t *map;
    bool local;

    if (local_ip4(ipaddr)) {
        map = local_hosts;
        local = true;
    } else {
        map = remote_hosts;
        local = false;
    }
    if (!hash_map_contains(map, &ipaddr)) {
        struct host_info *host = mempool_pealloc(sizeof(struct host_info));
        char *name;

        host->ip4_addr = ipaddr;
        host->local = local;
        if ((name = dns_cache_get(&host->ip4_addr))) {
            host->name = name;
        } else {
            host->name = NULL;
        }
        if (local) {
            memcpy(host->mac_addr, mac, ETH_ALEN);
        }
        hash_map_insert(map, &ipaddr, host);
        publish2(host_changed_publisher, host, (void *) 0x1);
    } else {
        struct host_info *host = hash_map_get(map, &ipaddr);

        if (!host->name) {
            char *name = dns_cache_get(&ipaddr);

            if (name) {
                host->name = name;
                publish2(host_changed_publisher, host, (void *) 0x0);
            }
        }
    }
}
