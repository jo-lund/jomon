#include <stddef.h>
#include "dns_cache.h"
#include "../hashmap.h"
#include "../signal.h"
#include "../hash.h"

#define CACHE_SIZE 1024

static hashmap_t *dns_cache;
static publisher_t *dns_cache_publisher;

void dns_cache_init()
{
    dns_cache = hashmap_init(CACHE_SIZE, hashdjb_uint32, compare_uint);
    dns_cache_publisher = publisher_init();
}

void dns_cache_free()
{
    hashmap_free(dns_cache);
    publisher_free(dns_cache_publisher);
}

void dns_cache_insert(uint32_t addr, char *name)
{
    if (dns_cache && hashmap_insert(dns_cache, UINT_TO_PTR(addr), name)) {
        publish2(dns_cache_publisher, UINT_TO_PTR(addr), name);
    }
}

void dns_cache_remove(uint32_t addr)
{
    if (dns_cache) {
        hashmap_remove(dns_cache, UINT_TO_PTR(addr));
    }
}

char *dns_cache_get(uint32_t addr)
{
    return dns_cache ? (char *) hashmap_get(dns_cache, UINT_TO_PTR(addr)) : NULL;
}

void dns_cache_clear()
{
    if (dns_cache) {
        hashmap_clear(dns_cache);
    }
}

void dns_cache_subscribe(dns_cache_fn fn)
{
    if (dns_cache_publisher) {
        add_subscription2(dns_cache_publisher, (publisher_fn2) fn);
    }
}

void dns_cache_unsubscribe(dns_cache_fn fn)
{
    if (dns_cache_publisher) {
        remove_subscription2(dns_cache_publisher, (publisher_fn2) fn);
    }
}
