#ifndef DNS_CACHE
#define DNS_CACHE

#include <stdint.h>

typedef void (*dns_cache_fn)(void *addr, char *name);

/* Initializes the DNS cache.
 *
 * Resources needs to be freed with dns_cache_free().
 */
void dns_cache_init(void);

/* Inserts element in to the cache
 *
 * TODO: Handle time to live
 */
void dns_cache_insert(uint32_t addr, char *name);

/* Removes element from the cache */
void dns_cache_remove(uint32_t addr);

/* Returns the name associated with the IPv4 address */
char *dns_cache_get(uint32_t addr);

/* Clears the DNS cache */
void dns_cache_clear(void);

/* Frees all memory used by the DNS cache */
void dns_cache_free(void);

void dns_cache_subscribe(dns_cache_fn fn);
void dns_cache_unsubscribe(dns_cache_fn fn);


#endif
