#include <stddef.h>
#include "dns_cache.h"
#include "../hashmap.h"
#include "../signal.h"

#define CACHE_SIZE 1024

static hash_map_t *dns_cache;
static publisher_t *dns_cache_publisher;

void dns_cache_init()
{
    dns_cache = hash_map_init(CACHE_SIZE, NULL, NULL);
    dns_cache_publisher = publisher_init();
}

void dns_cache_free()
{
    hash_map_free(dns_cache);
    publisher_free(dns_cache_publisher);
}

void dns_cache_insert(uint32_t *addr, char *name)
{
    if (hash_map_insert(dns_cache, addr, name)) {
        publish2(dns_cache_publisher, addr, name);
    }
}

void dns_cache_remove(uint32_t *addr)
{
    hash_map_remove(dns_cache, addr);
}

char *dns_cache_get(uint32_t *addr)
{
    return (char *) hash_map_get(dns_cache, addr);
}

void dns_cache_clear()
{
    hash_map_clear(dns_cache);
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
