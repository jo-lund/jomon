#ifndef HOST_ANALYZER_H
#define HOST_ANALYZER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "hashmap.h"

struct host_info {
    uint32_t ip4_addr;
    unsigned char mac_addr[ETHER_ADDR_LEN];
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

void host_analyzer_init(void);
void host_analyzer_free(void);
void host_analyzer_investigate(struct packet *p);
hashmap_t *host_analyzer_get_local(void);
hashmap_t *host_analyzer_get_remote(void);
void host_analyzer_subscribe(analyzer_host_fn fn);
void host_analyzer_unsubscribe(analyzer_host_fn fn);
void host_analyzer_clear(void);
struct host_info *host_get_ip4host(uint32_t addr);

#endif
