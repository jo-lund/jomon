#ifndef HOST_ANALYZER_H
#define HOST_ANALYZER_H

#include <netinet/if_ether.h>
#include "../hashmap.h"

struct host_info {
    uint32_t ip4_addr;
    unsigned char mac_addr[ETH_ALEN];
    char *name;
    char *os;
    bool local;
};

struct packet;

/*
 * Function that will be called when a host is added or updated. The second
 * argument specifies whether the host is new or not.
 */
typedef void (*analyzer_host_fn)(struct host_info *, bool);

void host_analyzer_init();
void host_analyzer_free();
void host_analyzer_investigate(struct packet *p);
hash_map_t *host_analyzer_get_local();
hash_map_t *host_analyzer_get_remote();
void host_analyzer_subscribe(analyzer_host_fn fn);
void host_analyzer_unsubscribe(analyzer_host_fn fn);

#endif
