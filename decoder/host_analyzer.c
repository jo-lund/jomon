#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "host_analyzer.h"
#include "packet.h"
#include "packet_ip.h"
#include "../signal.h"
#include "packet_dns.h"
#include "dns_cache.h"
#include "../hash.h"

#define TBLSZ 1024

static hashmap_t *local_hosts;
static hashmap_t *remote_hosts;
static publisher_t *host_changed_publisher;

static void handle_ip4(struct packet *p);
static void update_host(uint32_t addr, char *name);

void host_analyzer_init()
{
    local_hosts = hashmap_init(TBLSZ, hashdjb_uint32, compare_uint);
    remote_hosts = hashmap_init(TBLSZ, hashdjb_uint32, compare_uint);
    host_changed_publisher = publisher_init();
    dns_cache_subscribe(update_host);
}

void host_analyzer_free()
{
    hashmap_free(local_hosts);
    hashmap_free(remote_hosts);
    publisher_free(host_changed_publisher);
    dns_cache_unsubscribe(update_host);
}

void host_analyzer_investigate(struct packet *p)
{
    if (!local_hosts && !remote_hosts)
        return;

    switch (ethertype(p)) {
    case ETH_P_IP:
        handle_ip4(p);
        break;
    default:
        break;
    }
}

hashmap_t *host_analyzer_get_local()
{
    return local_hosts;
}

hashmap_t *host_analyzer_get_remote()
{
    return remote_hosts;
}

void host_analyzer_subscribe(analyzer_host_fn fn)
{
    add_subscription2(host_changed_publisher, (publisher_fn2) (void *) fn);
}

void host_analyzer_unsubscribe(analyzer_host_fn fn)
{
    remove_subscription2(host_changed_publisher, (publisher_fn2) (void *) fn);
}

void host_analyzer_clear()
{
    hashmap_clear(local_hosts);
    hashmap_clear(remote_hosts);
}

static bool filter_address(const uint32_t addr)
{
    if (addr == 0)
        return true;

    /* broadcast */
    if (addr == (uint32_t) ~0)
        return true;

    /* multicast: 224.0.0.0 - 239.255.255.255) */
    if ((addr & 0xff) >= 224 && (addr & 0xff) <= 239)
        return true;

    return false;
}

static bool local_ip4(const uint32_t addr)
{
    if ((addr & 0xff) == 10 || /* class A: 10.0.0.0 - 10.255.255.255 */
        (addr & 0xffff) == 43200) /* class C: 192.168.0.0 - 192.168.255.255 */
        return true;

    /* class B: 172.16.0.0 - 172.31.255.255 */
    uint32_t classb = (addr & 0xff) << 8 | (addr & 0xff00) >> 8;

    if (classb >= 44048 && classb <= 44063)
        return true;

    return false;
}

static void insert_host(uint32_t addr, const uint8_t *mac)
{
    hashmap_t *map;
    bool local;

    if (local_ip4(addr)) {
        map = local_hosts;
        local = true;
    } else {
        map = remote_hosts;
        local = false;
    }
    if (!hashmap_contains(map, UINT_TO_PTR(addr))) {
        struct host_info *host = mempool_alloc(sizeof(struct host_info));
        char *name;

        host->ip4_addr = addr;
        host->local = local;
        if ((name = dns_cache_get(host->ip4_addr))) {
            host->name = name;
        } else {
            host->name = NULL;
        }
        if (local) {
            memcpy(host->mac_addr, mac, ETH_ALEN);
        }
        hashmap_insert(map, UINT_TO_PTR(addr), host);
        publish2(host_changed_publisher, host, UINT_TO_PTR(0x1));
    }
}

static void update_host(const uint32_t addr, char *name)
{
    hashmap_t *map = local_ip4(addr) ? local_hosts : remote_hosts;
    struct host_info *host = hashmap_get(map, UINT_TO_PTR(addr));

    if (host && !host->name) {
        host->name = name;
        publish2(host_changed_publisher, host, UINT_TO_PTR(0x0));
    }
}

static void handle_ip4(struct packet *p)
{
    if (!filter_address(ipv4_src(p)))
        insert_host(ipv4_src(p), eth_src(p));
    if (!filter_address(ipv4_dst(p)))
        insert_host(ipv4_dst(p), eth_dst(p));
}
