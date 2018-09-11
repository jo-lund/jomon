#include <stddef.h>
#include "dns_cache.h"
#include "../hashmap.h"

#define CACHE_SIZE 1024

static hash_map_t *dns_cache;

void dns_cache_init()
{
    dns_cache = hash_map_init(CACHE_SIZE, NULL, NULL);
}

void dns_cache_free()
{
    hash_map_free(dns_cache);
}

void dns_cache_insert(uint32_t *addr, char *name)
{
    hash_map_insert(dns_cache, addr, name);
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
